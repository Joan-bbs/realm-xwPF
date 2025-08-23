#!/bin/bash

# 脚本版本
SCRIPT_VERSION="v1.8.0"

# 临时配置变量（仅在配置过程中使用）
NAT_LISTEN_PORT=""
NAT_LISTEN_IP=""
NAT_THROUGH_IP="::"
REMOTE_IP=""
REMOTE_PORT=""
EXIT_LISTEN_PORT=""
FORWARD_TARGET=""

# 配置变量
SECURITY_LEVEL=""  # 传输模式：standard, ws, tls_self, tls_ca, ws_tls_self, ws_tls_ca
TLS_CERT_PATH=""   # TLS证书路径
TLS_KEY_PATH=""    # TLS私钥路径
TLS_SERVER_NAME="" # TLS服务器名称(SNI)
WS_PATH=""         # WebSocket路径

RULE_ID=""
RULE_NAME=""

# 依赖工具列表
REQUIRED_TOOLS=("curl" "wget" "tar" "grep" "cut" "bc")

# 通用的字段初始化函数
init_rule_field() {
    local field_name="$1"
    local default_value="$2"

    if [ ! -d "$RULES_DIR" ]; then
        return 0
    fi

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            # 检查是否已有该字段
            if ! grep -q "^${field_name}=" "$rule_file"; then
                echo "${field_name}=\"${default_value}\"" >> "$rule_file"
            fi
        fi
    done
}

# 通用的服务重启后确认函数
restart_and_confirm() {
    local operation_name="$1"
    local batch_mode="$2"

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在重启服务以应用${operation_name}...${NC}"
        if service_restart; then
            echo -e "${GREEN}✓ 服务重启成功，${operation_name}已生效${NC}"
            return 0
        else
            echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            return 1
        fi
    fi
    return 0
}

# 颜色定义
RED='\033[0;31m'      # 错误、危险、禁用状态
GREEN='\033[0;32m'    # 成功、正常、启用状态
YELLOW='\033[1;33m'   # 警告、特殊状态、重要提示
BLUE='\033[0;34m'     # 信息、标识、中性操作
WHITE='\033[1;37m'    # 关闭状态、默认文本
NC='\033[0m'          # 重置颜色

# 全局多源下载配置
DOWNLOAD_SOURCES=(
    ""  # 官方源
    "https://ghfast.top/"
    "https://gh.222322.xyz/"
    "https://ghproxy.gpnu.org/"
)

# 全局超时配置
SHORT_CONNECT_TIMEOUT=5
SHORT_MAX_TIMEOUT=7
LONG_CONNECT_TIMEOUT=15
LONG_MAX_TIMEOUT=20

# 核心路径变量
REALM_PATH="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
MANAGER_CONF="${CONFIG_DIR}/manager.conf"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SYSTEMD_PATH="/etc/systemd/system/realm.service"
LOG_PATH="/var/log/realm.log"

# 转发配置管理路径
RULES_DIR="${CONFIG_DIR}/rules"

# 默认tls域名（双端Realm架构需要相同SNI）
DEFAULT_SNI_DOMAIN="www.tesla.com"

# 统一的realm配置模板
generate_base_config_template() {
    cat <<EOF
{
    "log": {
        "level": "info",
        "output": "${LOG_PATH}"
    },
    "dns": {
        "mode": "ipv4_and_ipv6",
        "nameservers": [
            "1.1.1.1:53",
            "8.8.8.8:53",
            "[2606:4700:4700::1111]:53",
            "[2001:4860:4860::8888]:53"
        ],
        "protocol": "tcp_and_udp",
        "min_ttl": 600,
        "max_ttl": 1800,
        "cache_size": 256
    },
    "network": {
        "no_tcp": false,
        "use_udp": true,
        "tcp_timeout": 5,
        "udp_timeout": 30,
        "tcp_keepalive": 12,
        "tcp_keepalive_probe": 3
    }
}
EOF
}

# 生成完整的realm配置文件
generate_complete_config() {
    local endpoints="$1"
    local config_path="${2:-$CONFIG_PATH}"

    # 获取基础配置模板
    local base_config=$(generate_base_config_template)

    # 移除基础配置的结尾大括号，准备添加endpoints
    base_config=$(echo "$base_config" | sed '$d')

    # 生成完整配置
    cat > "$config_path" <<EOF
$base_config,
    "endpoints": [$endpoints
    ]
}
EOF
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限运行。${NC}"
        exit 1
    fi
}

# 检测系统类型（仅支持Debian/Ubuntu）
detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi

    # 验证是否为支持的系统
    if ! command -v apt-get >/dev/null 2>&1; then
        echo -e "${RED}错误: 当前仅支持 Ubuntu/Debian 系统${NC}"
        echo -e "${YELLOW}检测到系统: $OS $VER${NC}"
        exit 1
    fi
}

# 检测netcat-openbsd是否已安装
check_netcat_openbsd() {
    # 检查netcat-openbsd包是否已安装
    dpkg -l netcat-openbsd >/dev/null 2>&1
    return $?
}

# 统一的依赖管理函数
manage_dependencies() {
    local mode="$1"  # "check" 或 "install"
    local missing_tools=()

    # 检查基础工具
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        elif [ "$mode" = "install" ]; then
            echo -e "${GREEN}✓${NC} $tool 已安装"
        fi
    done

    # 单独检查netcat-openbsd版本
    if ! check_netcat_openbsd; then
        missing_tools+=("nc")
        if [ "$mode" = "install" ]; then
            echo -e "${YELLOW}✗${NC} nc 需要安装netcat-openbsd版本"
        fi
    elif [ "$mode" = "install" ]; then
        echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 已安装"
    fi

    # 处理缺失的工具
    if [ ${#missing_tools[@]} -gt 0 ]; then
        if [ "$mode" = "check" ]; then
            echo -e "${RED}错误: 缺少必备工具: ${missing_tools[*]}${NC}"
            echo -e "${YELLOW}请先选择菜单选项1进行安装，或手动运行安装命令:${NC}"
            echo -e "${BLUE}curl -fsSL https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install${NC}"
            exit 1
        elif [ "$mode" = "install" ]; then
            echo -e "${YELLOW}需要安装以下工具: ${missing_tools[*]}${NC}"
            echo -e "${BLUE}使用 apt-get 安装依赖,下载中...${NC}"
            apt-get update -qq >/dev/null 2>&1

            for tool in "${missing_tools[@]}"; do
                case "$tool" in
                    "curl") apt-get install -y curl >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} curl 安装成功" ;;
                    "wget") apt-get install -y wget >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} wget 安装成功" ;;
                    "tar") apt-get install -y tar >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} tar 安装成功" ;;
                    "bc") apt-get install -y bc >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} bc 安装成功" ;;
                    "nc")
                        # 确保安装正确的netcat版本
                        apt-get remove -y netcat-traditional >/dev/null 2>&1
                        apt-get install -y netcat-openbsd >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 安装成功"
                        ;;
                esac
            done
        fi
    elif [ "$mode" = "install" ]; then
        echo -e "${GREEN}所有必备工具已安装完成${NC}"
    fi

    [ "$mode" = "install" ] && echo ""
}

# 安装依赖工具（向后兼容）
install_dependencies() {
    echo -e "${YELLOW}正在检查必备依赖工具...${NC}"
    manage_dependencies "install"
}

# 检查必备依赖工具（向后兼容）
check_dependencies() {
    manage_dependencies "check"
}

# 获取本机公网IP
get_public_ip() {
    local ip_type="$1"  # ipv4 或 ipv6
    local ip=""
    local curl_opts=""

    # 设置IPv6选项
    if [ "$ip_type" = "ipv6" ]; then
        curl_opts="-6"
    fi

    # 优先使用ipinfo.io
    ip=$(curl -s --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT $curl_opts https://ipinfo.io/ip 2>/dev/null | tr -d '\n\r ')
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
        echo "$ip"
        return 0
    fi

    # 备用cloudflare trace
    ip=$(curl -s --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT $curl_opts https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip=" | cut -d'=' -f2 | tr -d '\n\r ')
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
        echo "$ip"
        return 0
    fi

    echo ""
}

# 写入状态文件
write_manager_conf() {
    mkdir -p "$CONFIG_DIR"

    cat > "$MANAGER_CONF" <<EOF
# Realm 管理器配置文件
# 此文件由脚本自动生成，请勿手动修改

ROLE=$ROLE
INSTALL_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"
# 使用全局版本变量

# 新增配置选项
SECURITY_LEVEL=$SECURITY_LEVEL
TLS_CERT_PATH=$TLS_CERT_PATH
TLS_KEY_PATH=$TLS_KEY_PATH
TLS_SERVER_NAME=$TLS_SERVER_NAME
WS_PATH=$WS_PATH
EOF

    echo -e "${GREEN}✓ 状态文件已保存: $MANAGER_CONF${NC}"
}

# 读取状态文件
read_manager_conf() {
    if [ ! -f "$MANAGER_CONF" ]; then
        echo -e "${RED}错误: 状态文件不存在，请先运行安装${NC}"
        echo -e "${YELLOW}运行命令: ${GREEN}pf install${NC}"
        exit 1
    fi

    # 读取配置文件
    source "$MANAGER_CONF"

    # 验证必要变量
    if [ -z "$ROLE" ]; then
        echo -e "${RED}错误: 状态文件损坏，请重新安装${NC}"
        exit 1
    fi

}

# 检查端口占用（忽略realm自身占用）
# 返回值：0=端口可用或其他服务占用但用户选择继续，1=realm占用，2=用户取消
check_port_usage() {
    local port="$1"
    local service_name="$2"

    if [ -z "$port" ]; then
        return 0
    fi

    # 使用 ss 命令进行端口检测（Debian/Ubuntu标准工具）
    local port_check_cmd="ss -tulnp"

    # 查询端口占用情况
    local port_output=$($port_check_cmd 2>/dev/null | grep ":${port} ")
    if [ -n "$port_output" ]; then
        # 直接检查输出中是否包含realm进程
        if echo "$port_output" | grep -q "realm"; then
            # realm自身占用，返回特殊状态码
            echo -e "${GREEN}✓ 端口 $port 已被realm服务占用，支持单端口中转多落地配置${NC}"
            return 1
        else
            # 其他服务占用，显示警告
            echo -e "${YELLOW}警告: 端口 $port 已被其他服务占用${NC}"
            echo -e "${BLUE}占用进程信息:${NC}"
            echo "$port_output" | while read line; do
                echo "  $line"
            done

            read -p "是否继续配置？(y/n): " continue_config
            if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
                echo "配置已取消"
                exit 1
            fi
        fi
    fi
    # 端口可用时静默通过，不显示提示
    return 0
}

# 测试IP或域名的连通性
check_connectivity() {
    local target="$1"
    local port="$2"
    local timeout="${3:-3}"  # 支持可选的超时参数，默认3秒

    # 检查参数
    if [ -z "$target" ] || [ -z "$port" ]; then
        return 1
    fi

    # 使用nc检测连通性（netcat-openbsd已确保安装）
    nc -z -w"$timeout" "$target" "$port" >/dev/null 2>&1
    return $?
}

# 验证端口号格式
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    # IPv4格式检查
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    # IPv6格式检查（简化）
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *":"* ]]; then
        return 0
    fi
    return 1
}

# 验证转发目标地址（支持IP、域名、多地址）
validate_target_address() {
    local target="$1"

    # 检查是否为空
    if [ -z "$target" ]; then
        return 1
    fi

    # 检查是否包含逗号（多地址）
    if [[ "$target" == *","* ]]; then
        # 分割多地址并逐一验证
        IFS=',' read -ra ADDRESSES <<< "$target"
        for addr in "${ADDRESSES[@]}"; do
            addr=$(echo "$addr" | xargs)  # 去除空格
            if ! validate_single_address "$addr"; then
                return 1
            fi
        done
        return 0
    else
        # 单地址验证
        validate_single_address "$target"
    fi
}

# 验证单个地址（IP或域名）
validate_single_address() {
    local addr="$1"

    # IPv4或IPv6地址检查
    if validate_ip "$addr"; then
        return 0
    fi

    # 域名格式检查
    if [[ "$addr" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [[ "$addr" == "localhost" ]]; then
        return 0
    fi

    return 1
}

#--- 配置生成函数 ---

# 获取传输配置
get_transport_config() {
    local security_level="$1"
    local server_name="$2"
    local cert_path="$3"
    local key_path="$4"
    local role="$5"  # 角色参数：1=中转服务器(客户端), 2=出口服务器(服务端)
    local ws_path="$6"  # WebSocket路径参数

    case "$security_level" in
        "standard")
            echo ""
            ;;
        "ws")
            # WebSocket配置
            local ws_path_param="${ws_path:-/ws}"
            if [ "$role" = "1" ]; then
                # 中转服务器(客户端): WebSocket连接
                echo '"remote_transport": "ws;path='$ws_path_param'"'
            elif [ "$role" = "2" ]; then
                # 出口服务器(服务端): WebSocket监听
                echo '"listen_transport": "ws;path='$ws_path_param'"'
            fi
            ;;
        "tls_self")
            # TLS自签证书配置
            local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
            if [ "$role" = "1" ]; then
                # 中转服务器(客户端): 使用remote_transport连接到服务端，忽略证书验证
                echo '"remote_transport": "tls;sni='$sni_name';insecure"'
            elif [ "$role" = "2" ]; then
                # 出口服务器(服务端): 使用listen_transport生成自签证书
                echo '"listen_transport": "tls;servername='$sni_name'"'
            fi
            ;;
        "tls_ca")
            # TLS CA证书配置
            if [ "$role" = "1" ]; then
                # 中转服务器(客户端): 使用remote_transport连接到服务端
                local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
                echo '"remote_transport": "tls;sni='$sni_name'"'
            elif [ "$role" = "2" ]; then
                # 出口服务器(服务端): 使用listen_transport和用户提供的证书
                if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
                    echo '"listen_transport": "tls;cert='$cert_path';key='$key_path'"'
                else
                    echo ""
                fi
            fi
            ;;
        "ws_tls_self")
            # WebSocket+TLS自签证书配置
            local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
            local ws_path_param="${ws_path:-/ws}"
            if [ "$role" = "1" ]; then
                # 中转服务器(客户端): WebSocket+TLS自签
                echo '"remote_transport": "ws;host='$sni_name';path='$ws_path_param';tls;sni='$sni_name';insecure"'
            elif [ "$role" = "2" ]; then
                # 出口服务器(服务端): WebSocket+TLS自签
                echo '"listen_transport": "ws;host='$sni_name';path='$ws_path_param';tls;servername='$sni_name'"'
            fi
            ;;
        "ws_tls_ca")
            # WebSocket+TLS CA证书配置
            local sni_name="${server_name:-$DEFAULT_SNI_DOMAIN}"
            local ws_path_param="${ws_path:-/ws}"
            if [ "$role" = "1" ]; then
                # 中转服务器(客户端): WebSocket+TLS CA证书
                echo '"remote_transport": "ws;host='$sni_name';path='$ws_path_param';tls;sni='$sni_name'"'
            elif [ "$role" = "2" ]; then
                # 出口服务器(服务端): WebSocket+TLS CA证书
                if [ -n "$cert_path" ] && [ -n "$key_path" ]; then
                    echo '"listen_transport": "ws;host='$sni_name';path='$ws_path_param';tls;cert='$cert_path';key='$key_path'"'
                else
                    echo ""
                fi
            fi
            ;;
        *)
            echo ""
            ;;
    esac
}

# 内置日志管理函数（控制日志大小）
manage_log_size() {
    local log_file="$1"
    local max_size_mb="${2:-10}"  # 默认10MB限制
    local keep_size_mb="${3:-5}"   # 保留最后5MB

    # 安全检查：确保文件存在且可写
    if [ -f "$log_file" ] && [ -w "$log_file" ]; then
        local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
        local max_bytes=$((max_size_mb * 1024 * 1024))
        local keep_bytes=$((keep_size_mb * 1024 * 1024))

        if [ "$file_size" -gt "$max_bytes" ]; then
            # 安全截断：先备份再操作，失败时恢复
            if cp "$log_file" "${log_file}.backup" 2>/dev/null; then
                if tail -c "$keep_bytes" "$log_file" > "${log_file}.tmp" 2>/dev/null && mv "${log_file}.tmp" "$log_file" 2>/dev/null; then
                    rm -f "${log_file}.backup" 2>/dev/null
                else
                    # 操作失败，恢复备份
                    mv "${log_file}.backup" "$log_file" 2>/dev/null
                fi
            fi
        fi
    fi
}

# 生成转发endpoints配置
generate_forward_endpoints_config() {
    local target="$FORWARD_TARGET"
    local listen_ip="::"

    # 获取传输配置（出口服务器角色=2）
    local transport_config=$(get_transport_config "$SECURITY_LEVEL" "$TLS_SERVER_NAME" "$TLS_CERT_PATH" "$TLS_KEY_PATH" "2" "$WS_PATH")
    local transport_line=""
    if [ -n "$transport_config" ]; then
        transport_line=",
            $transport_config"
    fi

    # 检查是否为多地址
    if [[ "$target" == *","* ]]; then
        # 多地址配置：正确分离IP地址和端口
        local port="${target##*:}"
        local addresses_part="${target%:*}"
        IFS=',' read -ra ip_addresses <<< "$addresses_part"

        # 构建主地址（第一个地址+端口）
        local main_address="${ip_addresses[0]}:$port"
        local extra_addresses=""

        # 构建额外地址字符串（每个地址都加上端口）
        if [ ${#ip_addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#ip_addresses[@]}; i++)); do
                if [ -n "$extra_addresses" ]; then
                    extra_addresses="$extra_addresses, "
                fi
                extra_addresses="$extra_addresses\"${ip_addresses[i]}:$port\""
            done

            extra_addresses=",
        \"extra_remotes\": [$extra_addresses]"
        fi

        echo "
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${main_address}\"${extra_addresses}${transport_line}
        }"
    else
        # 单地址配置
        echo "
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${target}\"${transport_line}
        }"
    fi
}

#--- 转发配置管理函数 ---

# 初始化规则目录
init_rules_dir() {
    mkdir -p "$RULES_DIR"
    if [ ! -f "${RULES_DIR}/.initialized" ]; then
        touch "${RULES_DIR}/.initialized"
        echo -e "${GREEN}✓ 规则目录已初始化: $RULES_DIR${NC}"
    fi
}

# 规则ID验证函数
validate_rule_ids() {
    local rule_ids="$1"
    local valid_ids=()
    local invalid_ids=()

    # 解析逗号分隔的ID
    local ids_array
    IFS=',' read -ra ids_array <<< "$rule_ids"

    # 验证所有ID的有效性
    for id in "${ids_array[@]}"; do
        # 去除空格
        id=$(echo "$id" | xargs)
        if [[ "$id" =~ ^[0-9]+$ ]]; then
            local rule_file="${RULES_DIR}/rule-${id}.conf"
            if [ -f "$rule_file" ]; then
                valid_ids+=("$id")
            else
                invalid_ids+=("$id")
            fi
        else
            invalid_ids+=("$id")
        fi
    done

    # 输出结果（格式：valid_count|invalid_count|valid_ids|invalid_ids）
    echo "${#valid_ids[@]}|${#invalid_ids[@]}|${valid_ids[*]}|${invalid_ids[*]}"
}

# 规则ID解析函数
parse_rule_ids() {
    local input="$1"
    # 去除空格并返回清理后的ID列表
    echo "$input" | tr -d ' '
}

# 规则计数函数
get_active_rules_count() {
    local count=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file"; then
                    count=$((count + 1))
                fi
            fi
        done
    fi
    echo "$count"
}

# 生成新的规则ID
generate_rule_id() {
    local max_id=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                local id=$(basename "$rule_file" | sed 's/rule-\([0-9]*\)\.conf/\1/')
                if [ "$id" -gt "$max_id" ]; then
                    max_id=$id
                fi
            fi
        done
    fi
    echo $((max_id + 1))
}

# 读取规则文件
read_rule_file() {
    local rule_file="$1"
    if [ -f "$rule_file" ]; then
        source "$rule_file"
        # 向后兼容：为旧规则文件设置默认值
        RULE_NOTE="${RULE_NOTE:-}"
        MPTCP_MODE="${MPTCP_MODE:-off}"
        PROXY_MODE="${PROXY_MODE:-off}"
        return 0
    else
        return 1
    fi
}

# 获取负载均衡信息显示
get_balance_info_display() {
    local remote_host="$1"
    local balance_mode="$2"

    local balance_info=""
    case "$balance_mode" in
        "roundrobin")
            balance_info=" ${YELLOW}[轮询]${NC}"
            ;;
        "iphash")
            balance_info=" ${BLUE}[IP哈希]${NC}"
            ;;
        *)
            balance_info=" ${WHITE}[off]${NC}"
            ;;
    esac
    echo "$balance_info"
}

# 获取带权重的负载均衡信息显示
get_balance_info_with_weight() {
    local remote_host="$1"
    local balance_mode="$2"
    local weights="$3"
    local target_index="$4"

    local balance_info=""
    case "$balance_mode" in
        "roundrobin")
            balance_info=" ${YELLOW}[轮询]${NC}"
            ;;
        "iphash")
            balance_info=" ${BLUE}[IP哈希]${NC}"
            ;;
        *)
            balance_info=" ${WHITE}[off]${NC}"
            return 0
            ;;
    esac

    # 只有在负载均衡启用且有多个目标时才显示权重信息
    if [[ "$remote_host" == *","* ]]; then
        # 解析权重
        local weight_array
        if [ -n "$weights" ]; then
            IFS=',' read -ra weight_array <<< "$weights"
        else
            # 默认相等权重
            IFS=',' read -ra host_array <<< "$remote_host"
            for ((i=0; i<${#host_array[@]}; i++)); do
                weight_array[i]=1
            done
        fi

        # 计算总权重
        local total_weight=0
        for w in "${weight_array[@]}"; do
            total_weight=$((total_weight + w))
        done

        # 获取当前目标的权重
        local current_weight="${weight_array[$((target_index-1))]:-1}"

        # 计算百分比
        local percentage
        if [ "$total_weight" -gt 0 ]; then
            if command -v bc >/dev/null 2>&1; then
                percentage=$(echo "scale=1; $current_weight * 100 / $total_weight" | bc 2>/dev/null || echo "0.0")
            else
                percentage=$(awk "BEGIN {printf \"%.1f\", $current_weight * 100 / $total_weight}")
            fi
        else
            percentage="0.0"
        fi

        balance_info="$balance_info ${GREEN}[权重: $current_weight]${NC} ${BLUE}($percentage%)${NC}"
    fi

    echo "$balance_info"
}

# 检查目标服务器是否启用
is_target_enabled() {
    local target_index="$1"
    local target_states="$2"
    local state_key="target_${target_index}"

    if [[ "$target_states" == *"$state_key:false"* ]]; then
        echo "false"
    else
        echo "true"
    fi
}

# 读取并检查是否是中转服务器规则（会设置全局变量）
read_and_check_relay_rule() {
    local rule_file="$1"
    if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
        return 0
    else
        return 1
    fi
}

# 通用规则列表显示函数
# 参数: display_mode (management|mptcp|proxy)
list_rules_with_info() {
    local display_mode="${1:-management}"

    if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 1
    fi

    # 根据显示模式设置标题
    case "$display_mode" in
        "mptcp")
            echo -e "${BLUE}当前规则列表:${NC}"
            echo ""
            ;;
        "proxy")
            echo -e "${BLUE}当前规则列表:${NC}"
            echo ""
            ;;
        "management"|*)
            # 管理模式显示分类标题
            ;;
    esac

    # 处理中转服务器规则（仅管理模式需要分类显示）
    local has_relay_rules=false
    local relay_count=0

    if [ "$display_mode" = "management" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_and_check_relay_rule "$rule_file"; then
                    if [ "$has_relay_rules" = false ]; then
                        echo -e "${GREEN}中转服务器:${NC}"
                        has_relay_rules=true
                    fi
                    relay_count=$((relay_count + 1))

                    # 显示规则信息
                    display_single_rule_info "$rule_file" "$display_mode"
                fi
            fi
        done
    fi

    # 处理所有规则（非管理模式）或落地服务器规则（管理模式）
    local has_exit_rules=false
    local exit_count=0
    local has_rules=false

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                has_rules=true

                if [ "$display_mode" = "management" ]; then
                    # 管理模式：只显示落地服务器规则
                    if [ "$RULE_ROLE" = "2" ]; then
                        if [ "$has_exit_rules" = false ]; then
                            if [ "$has_relay_rules" = true ]; then
                                echo ""
                            fi
                            echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                            has_exit_rules=true
                        fi
                        exit_count=$((exit_count + 1))
                        display_single_rule_info "$rule_file" "$display_mode"
                    fi
                else
                    # 其他模式：显示所有规则
                    display_single_rule_info "$rule_file" "$display_mode"
                fi
            fi
        fi
    done

    if [ "$display_mode" != "management" ] && [ "$has_rules" = false ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 1
    fi

    return 0
}

# 获取规则状态显示信息（MPTCP和Proxy状态）
get_rule_status_display() {
    local security_display="$1"
    local note_display="$2"

    # 添加MPTCP状态显示
    local mptcp_mode="${MPTCP_MODE:-off}"
    local mptcp_display=""
    if [ "$mptcp_mode" != "off" ]; then
        local mptcp_text=$(get_mptcp_mode_display "$mptcp_mode")
        local mptcp_color=$(get_mptcp_mode_color "$mptcp_mode")
        mptcp_display=" | MPTCP: ${mptcp_color}$mptcp_text${NC}"
    fi

    # 添加Proxy状态显示
    local proxy_mode="${PROXY_MODE:-off}"
    local proxy_display=""
    if [ "$proxy_mode" != "off" ]; then
        local proxy_text=$(get_proxy_mode_display "$proxy_mode")
        local proxy_color=$(get_proxy_mode_color "$proxy_mode")
        proxy_display=" | Proxy: ${proxy_color}$proxy_text${NC}"
    fi

    echo -e "    安全: ${YELLOW}$security_display${NC}${mptcp_display}${proxy_display}${note_display}"
}

# 显示单个规则信息的辅助函数
display_single_rule_info() {
    local rule_file="$1"
    local display_mode="$2"

    if ! read_rule_file "$rule_file"; then
        return 1
    fi

    local status_color="${GREEN}"
    local status_text="启用"
    if [ "$ENABLED" != "true" ]; then
        status_color="${RED}"
        status_text="禁用"
    fi

    # 基础信息显示
    case "$display_mode" in
        "mptcp")
            local mptcp_mode="${MPTCP_MODE:-off}"
            local mptcp_display=$(get_mptcp_mode_display "$mptcp_mode")
            local mptcp_color=$(get_mptcp_mode_color "$mptcp_mode")
            echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME | 状态: ${status_color}$status_text${NC} | MPTCP: ${mptcp_color}$mptcp_display${NC}"
            ;;
        "proxy")
            local proxy_mode="${PROXY_MODE:-off}"
            local proxy_display=$(get_proxy_mode_display "$proxy_mode")
            local proxy_color=$(get_proxy_mode_color "$proxy_mode")
            echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME | 状态: ${status_color}$status_text${NC} | Proxy: ${proxy_color}$proxy_display${NC}"
            ;;
        "management"|*)
            if [ "$RULE_ROLE" = "2" ]; then
                # 落地服务器使用FORWARD_TARGET
                local target_host="${FORWARD_TARGET%:*}"
                local target_port="${FORWARD_TARGET##*:}"
                local display_target=$(smart_display_target "$target_host")
                local rule_display_name="$RULE_NAME"
                # 落地服务器不需要负载均衡信息
                local balance_info=""
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $display_target:$target_port) [${status_color}$status_text${NC}]$balance_info"
            else
                # 中转服务器
                local display_target=$(smart_display_target "$REMOTE_HOST")
                local rule_display_name="$RULE_NAME"
                # 构建负载均衡信息
                local balance_mode="${BALANCE_MODE:-off}"
                local balance_info=$(get_balance_info_display "$REMOTE_HOST" "$balance_mode")
                local through_display="${THROUGH_IP:-::}"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info"
            fi
            return 0  # 管理模式不需要额外的转发信息显示
            ;;
    esac

    # 显示转发信息（仅用于mptcp和proxy模式）
    if [ "$RULE_ROLE" = "2" ]; then
        # 落地服务器使用FORWARD_TARGET
        local target_host="${FORWARD_TARGET%:*}"
        local target_port="${FORWARD_TARGET##*:}"
        local display_target=$(smart_display_target "$target_host")
        local display_ip="::"
        echo -e "  监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
    else
        # 中转服务器使用REMOTE_HOST
        local display_target=$(smart_display_target "$REMOTE_HOST")
        local display_ip="${NAT_LISTEN_IP:-::}"
        local through_display="${THROUGH_IP:-::}"
        echo -e "  监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
    fi
    echo ""
}




# 根据序号获取规则ID
get_rule_id_by_index() {
    local index="$1"
    local count=0

    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                count=$((count + 1))
                if [ "$count" -eq "$index" ]; then
                    echo "$RULE_ID"
                    return 0
                fi
            fi
        fi
    done

    return 1
}

# 获取规则总数（保持向后兼容）
get_rules_count() {
    get_active_rules_count
}

# 列出所有规则（详细信息，用于查看）
list_all_rules() {
    echo -e "${YELLOW}=== 所有转发规则 ===${NC}"
    echo ""

    if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 0
    fi

    local count=0
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file"; then
                count=$((count + 1))
                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                echo -e "ID ${BLUE}$RULE_ID${NC}: $RULE_NAME"
                # 构建安全级别显示
                local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                local note_display=""
                if [ -n "$RULE_NOTE" ]; then
                    note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                fi
                echo -e "  通用配置: ${YELLOW}$security_display${NC}${note_display} | 状态: ${status_color}$status_text${NC}"
                # 根据规则角色显示不同的转发信息
                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    local display_ip="::"
                    echo -e "  监听: ${GREEN}${LISTEN_IP:-$display_ip}:$LISTEN_PORT${NC} → 转发: ${GREEN}$FORWARD_TARGET${NC}"
                else
                    # 中转服务器使用REMOTE_HOST:REMOTE_PORT，显示格式：中转: 监听IP:端口 → 出口IP → 目标IP:端口
                    local display_ip="${NAT_LISTEN_IP:-::}"
                    local through_display="${THROUGH_IP:-::}"
                    echo -e "  中转: ${GREEN}${LISTEN_IP:-$display_ip}:$LISTEN_PORT${NC} → ${GREEN}$through_display${NC} → ${GREEN}$REMOTE_HOST:$REMOTE_PORT${NC}"
                fi
                echo -e "  创建时间: $CREATED_TIME"
                echo ""
            fi
        fi
    done

    echo -e "${BLUE}共找到 $count 个配置${NC}"
}

# 添加转发配置
interactive_add_rule() {
    echo -e "${YELLOW}=== 添加新转发配置 ===${NC}"
    echo ""

    # 角色选择
    echo "请选择新配置的角色:"
    echo -e "${GREEN}[1]${NC} 中转服务器"
    echo -e "${GREEN}[2]${NC} 服务端(落地)服务器 (双端Realm架构)"
    echo "双端Realm架构解密用于：隧道,MPTCP，Proxy Protocol"
    echo ""
    local RULE_ROLE
    while true; do
        read -p "请输入数字 [1-2]: " RULE_ROLE
        case $RULE_ROLE in
            1)
                echo -e "${GREEN}已选择: 中转服务器${NC}"
                break
                ;;
            2)
                echo -e "${GREEN}已选择: 服务端(落地)服务器 (双端Realm架构)${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-2${NC}"
                ;;
        esac
    done
    echo ""

    # 保存当前变量状态（避免污染全局变量）
    local ORIG_ROLE="$ROLE"
    local ORIG_NAT_LISTEN_PORT="$NAT_LISTEN_PORT"
    local ORIG_REMOTE_IP="$REMOTE_IP"
    local ORIG_REMOTE_PORT="$REMOTE_PORT"
    local ORIG_EXIT_LISTEN_PORT="$EXIT_LISTEN_PORT"
    local ORIG_FORWARD_TARGET="$FORWARD_TARGET"
    local ORIG_SECURITY_LEVEL="$SECURITY_LEVEL"
    local ORIG_TLS_SERVER_NAME="$TLS_SERVER_NAME"
    local ORIG_TLS_CERT_PATH="$TLS_CERT_PATH"
    local ORIG_TLS_KEY_PATH="$TLS_KEY_PATH"

    # 临时设置角色并调用现有配置函数
    ROLE="$RULE_ROLE"

    if [ "$RULE_ROLE" -eq 1 ]; then
        # 中转服务器配置 - 复用现有函数
        configure_nat_server
        if [ $? -ne 0 ]; then
            echo "配置已取消"
            return 1
        fi
    elif [ "$RULE_ROLE" -eq 2 ]; then
        # 出口服务器配置 - 复用现有函数
        configure_exit_server
        if [ $? -ne 0 ]; then
            echo "配置已取消"
            return 1
        fi
    fi

    # 创建规则文件
    echo -e "${YELLOW}正在创建转发配置...${NC}"
    init_rules_dir
    local rule_id=$(generate_rule_id)
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"

    if [ "$RULE_ROLE" -eq 1 ]; then
        # 中转服务器规则
        cat > "$rule_file" <<EOF
RULE_ID=$rule_id
RULE_NAME="中转"
RULE_ROLE="1"
SECURITY_LEVEL="$SECURITY_LEVEL"
LISTEN_PORT="$NAT_LISTEN_PORT"
LISTEN_IP="${NAT_LISTEN_IP:-::}"
THROUGH_IP="$NAT_THROUGH_IP"
REMOTE_HOST="$REMOTE_IP"
REMOTE_PORT="$REMOTE_PORT"
TLS_SERVER_NAME="$TLS_SERVER_NAME"
TLS_CERT_PATH="$TLS_CERT_PATH"
TLS_KEY_PATH="$TLS_KEY_PATH"
WS_PATH="$WS_PATH"
RULE_NOTE="$RULE_NOTE"
ENABLED="true"
CREATED_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"

# 负载均衡配置
BALANCE_MODE="off"
TARGET_STATES=""
WEIGHTS=""

# 故障转移配置
FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"

# MPTCP配置
MPTCP_MODE="off"

# Proxy配置
PROXY_MODE="off"
EOF

        echo -e "${GREEN}✓ 中转配置已创建 (ID: $rule_id)${NC}"
        echo -e "${BLUE}配置详情: $REMOTE_IP:$REMOTE_PORT${NC}"

    elif [ "$RULE_ROLE" -eq 2 ]; then
        # 出口服务器规则
        cat > "$rule_file" <<EOF
RULE_ID=$rule_id
RULE_NAME="落地"
RULE_ROLE="2"
SECURITY_LEVEL="$SECURITY_LEVEL"
LISTEN_PORT="$EXIT_LISTEN_PORT"
FORWARD_TARGET="$FORWARD_TARGET"
TLS_SERVER_NAME="$TLS_SERVER_NAME"
TLS_CERT_PATH="$TLS_CERT_PATH"
TLS_KEY_PATH="$TLS_KEY_PATH"
WS_PATH="$WS_PATH"
RULE_NOTE="$RULE_NOTE"
ENABLED="true"
CREATED_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"

# 负载均衡配置
BALANCE_MODE="off"
TARGET_STATES=""
WEIGHTS=""

# 故障转移配置
FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"

# MPTCP配置
MPTCP_MODE="off"

# Proxy配置
PROXY_MODE="off"
EOF

        echo -e "${GREEN}✓ 转发配置已创建 (ID: $rule_id)${NC}"
        echo -e "${BLUE}配置详情: $FORWARD_TARGET${NC}"
    fi

    # 恢复原始变量状态
    ROLE="$ORIG_ROLE"
    NAT_LISTEN_PORT="$ORIG_NAT_LISTEN_PORT"
    REMOTE_IP="$ORIG_REMOTE_IP"
    REMOTE_PORT="$ORIG_REMOTE_PORT"
    EXIT_LISTEN_PORT="$ORIG_EXIT_LISTEN_PORT"
    FORWARD_TARGET="$ORIG_FORWARD_TARGET"
    SECURITY_LEVEL="$ORIG_SECURITY_LEVEL"
    TLS_SERVER_NAME="$ORIG_TLS_SERVER_NAME"
    TLS_CERT_PATH="$ORIG_TLS_CERT_PATH"
    TLS_KEY_PATH="$ORIG_TLS_KEY_PATH"

    echo ""
    return 0
}

# 删除规则
delete_rule() {
    local rule_id="$1"
    local skip_confirm="${2:-false}"
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"

    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    # 读取规则信息
    if read_rule_file "$rule_file"; then
        # 只有在不跳过确认时才显示详情和询问
        if [ "$skip_confirm" != "true" ]; then
            echo -e "${YELLOW}即将删除规则:${NC}"
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC}"
            echo -e "${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
            echo -e "${BLUE}监听端口: ${GREEN}$LISTEN_PORT${NC}"
            echo ""

            read -p "确认删除此规则？(y/n): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                echo "删除已取消"
                return 1
            fi
        fi

        # 删除规则文件
        if rm -f "$rule_file"; then
            echo -e "${GREEN}✓ 规则 $rule_id 已删除${NC}"
            return 0
        else
            echo -e "${RED}✗ 规则 $rule_id 删除失败${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法读取规则文件${NC}"
        return 1
    fi
}

# 批量删除规则
batch_delete_rules() {
    local rule_ids="$1"

    # 使用验证函数
    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    # 检查是否有无效ID
    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    # 检查是否有有效ID
    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    # 转换为数组
    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    # 显示所有要删除的规则信息
    echo -e "${YELLOW}即将删除以下规则:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC} | ${BLUE}监听端口: ${GREEN}$LISTEN_PORT${NC}"
        fi
    done
    echo ""

    # 批量确认删除
    read -p "确认删除以上 $valid_count 个规则？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local deleted_count=0
        # 循环调用delete_rule，跳过单个确认
        for id in "${valid_ids_array[@]}"; do
            if delete_rule "$id" "true"; then
                deleted_count=$((deleted_count + 1))
            fi
        done
        echo ""
        echo -e "${GREEN}批量删除完成，共删除 $deleted_count 个规则${NC}"
        return 0
    else
        echo "批量删除已取消"
        return 1
    fi
}

# 启用/禁用规则
toggle_rule() {
    local rule_id="$1"
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"

    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    # 读取当前状态
    if read_rule_file "$rule_file"; then
        local new_status
        if [ "$ENABLED" = "true" ]; then
            new_status="false"
            echo -e "${YELLOW}正在禁用规则: $RULE_NAME${NC}"
        else
            new_status="true"
            echo -e "${YELLOW}正在启用规则: $RULE_NAME${NC}"
        fi

        # 更新状态
        sed -i "s/ENABLED=\".*\"/ENABLED=\"$new_status\"/" "$rule_file"

        if [ "$new_status" = "true" ]; then
            echo -e "${GREEN}✓ 规则已启用${NC}"
        else
            echo -e "${GREEN}✓ 规则已禁用${NC}"
        fi

        return 0
    else
        echo -e "${RED}错误: 无法读取规则文件${NC}"
        return 1
    fi
}

# 生成导出元数据文件
generate_export_metadata() {
    local metadata_file="$1"
    local rules_count="$2"

    cat > "$metadata_file" <<EOF
# xwPF配置包元数据
EXPORT_TIME=$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')
SCRIPT_VERSION=$SCRIPT_VERSION
EXPORT_HOST=$(hostname 2>/dev/null || echo "unknown")
RULES_COUNT=$rules_count
HAS_MANAGER_CONF=$([ -f "$MANAGER_CONF" ] && echo "true" || echo "false")
HAS_HEALTH_STATUS=$([ -f "$HEALTH_STATUS_FILE" ] && echo "true" || echo "false")
PACKAGE_VERSION=1.0
EOF
}

# 导出配置包
export_config_package() {
    echo -e "${YELLOW}=== 导出配置包 ===${NC}"
    echo ""

    # 检查是否有可导出的配置
    local rules_count=$(get_active_rules_count)

    local has_manager_conf=false
    [ -f "$MANAGER_CONF" ] && has_manager_conf=true

    if [ $rules_count -eq 0 ] && [ "$has_manager_conf" = false ]; then
        echo -e "${RED}没有可导出的配置数据${NC}"
        echo ""
        read -p "按回车键返回..."
        return 1
    fi

    # 显示导出内容摘要
    echo -e "${BLUE}将要导出的完整配置：${NC}"
    echo -e "  转发规则: ${GREEN}$rules_count 条${NC}"
    [ "$has_manager_conf" = true ] && echo -e "  管理状态: ${GREEN}包含${NC}"
    [ -f "$HEALTH_STATUS_FILE" ] && echo -e "  健康监控: ${GREEN}包含${NC}"
    echo -e "  备注权重: ${GREEN}完整保留${NC}"
    echo ""

    # 确认导出
    read -p "确认导出配置包？(y/n): " confirm
    if ! echo "$confirm" | grep -qE "^[Yy]$"; then
        echo -e "${BLUE}已取消导出操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 导出到/usr/local/bin目录
    local export_dir="/usr/local/bin"

    # 生成导出文件名
    local timestamp=$(get_gmt8_time '+%Y%m%d_%H%M%S')
    local export_filename="xwPF_config_${timestamp}.tar.gz"
    local export_path="${export_dir}/${export_filename}"

    # 创建临时目录
    local temp_dir=$(mktemp -d)
    local package_dir="${temp_dir}/xwPF_config"
    mkdir -p "$package_dir"

    echo ""
    echo -e "${YELLOW}正在收集配置数据...${NC}"

    # 生成元数据文件
    generate_export_metadata "${package_dir}/metadata.txt" "$rules_count"

    # 复制规则文件
    if [ $rules_count -gt 0 ]; then
        mkdir -p "${package_dir}/rules"
        cp "${RULES_DIR}"/rule-*.conf "${package_dir}/rules/" 2>/dev/null
        echo -e "${GREEN}✓${NC} 已收集 $rules_count 个规则文件"
    fi

    # 复制管理配置文件
    if [ -f "$MANAGER_CONF" ]; then
        cp "$MANAGER_CONF" "${package_dir}/"
        echo -e "${GREEN}✓${NC} 已收集管理配置文件"
    fi

    # 复制健康状态文件
    if [ -f "$HEALTH_STATUS_FILE" ]; then
        cp "$HEALTH_STATUS_FILE" "${package_dir}/health_status.conf"
        echo -e "${GREEN}✓${NC} 已收集健康状态文件"
    fi

    # 复制MPTCP配置文件
    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
    if [ -f "$mptcp_conf" ]; then
        cp "$mptcp_conf" "${package_dir}/90-enable-MPTCP.conf"
        echo -e "${GREEN}✓${NC} 已收集MPTCP系统配置文件"
    fi

    # 导出MPTCP端点配置
    if command -v ip >/dev/null 2>&1 && /usr/bin/ip mptcp endpoint show >/dev/null 2>&1; then
        local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
        if [ -n "$endpoints_output" ]; then
            echo "$endpoints_output" > "${package_dir}/mptcp_endpoints.conf"
            echo -e "${GREEN}✓${NC} 已收集MPTCP端点配置"
        fi
    fi

    # 创建压缩包
    echo -e "${YELLOW}正在创建压缩包...${NC}"
    cd "$temp_dir"
    if tar -czf "$export_path" xwPF_config/ >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 配置包导出成功${NC}"
        echo ""
        echo -e "${BLUE}导出信息：${NC}"
        echo -e "  文件名: ${GREEN}$export_filename${NC}"
        echo -e "  路径: ${GREEN}$export_path${NC}"
        echo -e "  大小: ${GREEN}$(du -h "$export_path" 2>/dev/null | cut -f1)${NC}"
    else
        echo -e "${RED}✗ 配置包创建失败${NC}"
        rm -rf "$temp_dir"
        read -p "按回车键返回..."
        return 1
    fi

    # 清理临时目录
    rm -rf "$temp_dir"

    echo ""
    read -p "按回车键返回..."
}

# 导出配置包(包含查看配置)
export_config_with_view() {
    echo -e "${YELLOW}=== 查看配置文件 ===${NC}"
    echo -e "${BLUE}当前生效配置文件:${NC}"
    echo -e "${YELLOW}文件: $CONFIG_PATH${NC}"
    echo ""

    if [ -f "$CONFIG_PATH" ]; then
        cat "$CONFIG_PATH" | sed 's/^/  /'
    else
        echo -e "${RED}配置文件不存在${NC}"
    fi

    echo ""
    echo "是否一键导出当前全部文件架构？"
    echo -e "${GREEN}1.${NC}  一键导出为压缩包 "
    echo -e "${GREEN}0.${NC} 返回菜单"
    echo ""
    read -p "请输入选择 [0-1]: " export_choice
    echo ""

    case $export_choice in
        1)
            export_config_package
            ;;
        0)
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            read -p "按回车键继续..."
            ;;
    esac
}

# 验证配置包内容结构
validate_config_package_content() {
    local package_file="$1"
    local temp_dir=$(mktemp -d)

    # 解压到临时目录
    if ! tar -xzf "$package_file" -C "$temp_dir" >/dev/null 2>&1; then
        rm -rf "$temp_dir"
        return 1
    fi

    # 查找包含metadata.txt的目录（不依赖包名）
    local config_dir=""
    for dir in "$temp_dir"/*; do
        if [ -d "$dir" ] && [ -f "$dir/metadata.txt" ]; then
            config_dir="$dir"
            break
        fi
    done

    if [ -z "$config_dir" ]; then
        rm -rf "$temp_dir"
        return 1
    fi

    # 输出配置目录路径供后续使用
    echo "$config_dir"
    return 0
}

# 导入配置包
import_config_package() {
    echo -e "${YELLOW}=== 导入配置包 ===${NC}"
    echo ""

    # 输入配置包路径
    read -p "请输入配置包的完整路径：" package_path
    echo ""

    if [ -z "$package_path" ]; then
        echo -e "${BLUE}已取消操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    if [ ! -f "$package_path" ]; then
        echo -e "${RED}文件不存在: $package_path${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 验证并获取配置目录
    echo -e "${YELLOW}正在验证配置包...${NC}"
    local config_dir=$(validate_config_package_content "$package_path")
    if [ $? -ne 0 ] || [ -z "$config_dir" ]; then
        echo -e "${RED}无效的配置包文件${NC}"
        read -p "按回车键返回..."
        return
    fi

    local selected_filename=$(basename "$package_path")

    echo -e "${BLUE}配置包: ${GREEN}$selected_filename${NC}"

    # 显示导入预览
    if [ -f "${config_dir}/metadata.txt" ]; then
        source "${config_dir}/metadata.txt"
        echo -e "${BLUE}配置包信息：${NC}"
        echo -e "  导出时间: ${GREEN}$EXPORT_TIME${NC}"
        echo -e "  脚本版本: ${GREEN}$SCRIPT_VERSION${NC}"
        echo -e "  规则数量: ${GREEN}$RULES_COUNT${NC}"
        echo ""
    fi

    # 统计当前配置
    local current_rules=$(get_active_rules_count)

    echo -e "${YELLOW}当前规则数量: $current_rules${NC}"
    echo -e "${YELLOW}即将导入规则: $RULES_COUNT${NC}"
    echo ""
    echo -e "${RED}警告: 导入操作将覆盖所有现有配置！${NC}"
    echo ""

    # 确认导入
    read -p "确认导入配置包？(y/n): " confirm
    if ! echo "$confirm" | grep -qE "^[Yy]$"; then
        echo -e "${BLUE}已取消导入操作${NC}"
        rm -rf "$(dirname "$config_dir")"
        read -p "按回车键返回..."
        return
    fi

    # 执行导入
    echo ""
    echo -e "${YELLOW}正在导入配置...${NC}"

    # 清理现有配置
    echo -e "${BLUE}正在清理现有配置...${NC}"
    if [ -d "$RULES_DIR" ]; then
        rm -f "${RULES_DIR}"/rule-*.conf 2>/dev/null
    fi
    rm -f "$MANAGER_CONF" 2>/dev/null
    rm -f "$HEALTH_STATUS_FILE" 2>/dev/null

    # 初始化目录
    init_rules_dir

    # 恢复配置数据
    local imported_count=0

    # 恢复规则文件
    if [ -d "${config_dir}/rules" ]; then
        for rule_file in "${config_dir}/rules"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                local rule_name=$(basename "$rule_file")
                cp "$rule_file" "${RULES_DIR}/"
                imported_count=$((imported_count + 1))
                echo -e "${GREEN}✓${NC} 恢复规则文件: $rule_name"
            fi
        done
    fi

    # 恢复管理配置文件
    if [ -f "${config_dir}/manager.conf" ]; then
        cp "${config_dir}/manager.conf" "$MANAGER_CONF"
        echo -e "${GREEN}✓${NC} 恢复管理配置文件"
    fi

    # 恢复健康状态文件
    if [ -f "${config_dir}/health_status.conf" ]; then
        cp "${config_dir}/health_status.conf" "$HEALTH_STATUS_FILE"
        echo -e "${GREEN}✓${NC} 恢复健康状态文件"
    fi

    # 恢复MPTCP系统配置文件
    if [ -f "${config_dir}/90-enable-MPTCP.conf" ]; then
        local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
        cp "${config_dir}/90-enable-MPTCP.conf" "$mptcp_conf"
        echo -e "${GREEN}✓${NC} 恢复MPTCP系统配置文件"
        # 立即应用MPTCP配置
        sysctl -p "$mptcp_conf" >/dev/null 2>&1
    fi

    # 恢复MPTCP端点配置
    if [ -f "${config_dir}/mptcp_endpoints.conf" ] && command -v ip >/dev/null 2>&1; then
        echo -e "${YELLOW}正在恢复MPTCP端点配置...${NC}"
        # 先清理现有端点
        /usr/bin/ip mptcp endpoint flush 2>/dev/null
        # 恢复端点配置
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                # 解析端点信息：IP地址 id 数字 类型 dev 接口名
                local addr=$(echo "$line" | awk '{print $1}')
                local dev=$(echo "$line" | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

                # 解析三种端点模式
                local flags=""
                if echo "$line" | grep -q "subflow.*fullmesh"; then
                    flags="subflow fullmesh"
                elif echo "$line" | grep -q "subflow.*backup"; then
                    flags="subflow backup"
                elif echo "$line" | grep -q "signal"; then
                    flags="signal"
                fi

                if [ -n "$addr" ] && [ -n "$dev" ] && [ -n "$flags" ]; then
                    /usr/bin/ip mptcp endpoint add "$addr" dev "$dev" $flags 2>/dev/null
                fi
            fi
        done < "${config_dir}/mptcp_endpoints.conf"
        echo -e "${GREEN}✓${NC} 恢复MPTCP端点配置"
    fi

    # 清理临时目录
    rm -rf "$(dirname "$config_dir")"

    if [ $imported_count -gt 0 ]; then
        echo -e "${GREEN}✓ 配置导入成功，共恢复 $imported_count 个规则${NC}"
        echo ""
        echo -e "${YELLOW}正在重启服务以应用新配置...${NC}"
        service_restart
        echo ""
        echo -e "${GREEN}配置导入完成！${NC}"
    else
        echo -e "${RED}✗ 配置导入失败${NC}"
    fi

    echo ""
    read -p "按回车键返回..."
}

# 转发配置管理菜单
rules_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 转发配置管理 ===${NC}"
        echo ""

        # 显示服务状态
        local status=$(systemctl is-active realm 2>/dev/null)
        if [ "$status" = "active" ]; then
            echo -e "服务状态: ${GREEN}●${NC} 运行中"
        else
            echo -e "服务状态: ${RED}●${NC} 已停止"
        fi

        # 显示详细配置统计
        local enabled_count=0
        local disabled_count=0
        if [ -d "$RULES_DIR" ]; then
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file"; then
                        if [ "$ENABLED" = "true" ]; then
                            enabled_count=$((enabled_count + 1))
                        else
                            disabled_count=$((disabled_count + 1))
                        fi
                    fi
                fi
            done
        fi

        if [ "$enabled_count" -gt 0 ] || [ "$disabled_count" -gt 0 ]; then
            # 多规则模式
            local total_count=$((enabled_count + disabled_count))
            echo -e "配置模式: ${GREEN}多规则模式${NC} (${GREEN}$enabled_count${NC} 启用 / ${YELLOW}$disabled_count${NC} 禁用 / 共 $total_count 个)"

            # 按服务器类型分组显示启用的规则
            if [ "$enabled_count" -gt 0 ]; then
                # 中转服务器规则
                local has_relay_rules=false
                local relay_count=0
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "1" ]; then
                            if [ "$has_relay_rules" = false ]; then
                                echo -e "${GREEN}中转服务器:${NC}"
                                has_relay_rules=true
                            fi
                            relay_count=$((relay_count + 1))
                            # 显示详细的转发配置信息
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local rule_display_name="$RULE_NAME"
                            local display_ip="${NAT_LISTEN_IP:-::}"
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                            fi
                            # 显示状态信息
                            get_rule_status_display "$security_display" "$note_display"

                        fi
                    fi
                done

                # 落地服务器规则
                local has_exit_rules=false
                local exit_count=0
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "2" ]; then
                            if [ "$has_exit_rules" = false ]; then
                                if [ "$has_relay_rules" = true ]; then
                                    echo ""
                                fi
                                echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                                has_exit_rules=true
                            fi
                            exit_count=$((exit_count + 1))
                            # 显示详细的转发配置信息
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                            # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            local rule_display_name="$RULE_NAME"
                            local display_ip="::"
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                            fi
                            # 显示状态信息
                            get_rule_status_display "$security_display" "$note_display"

                        fi
                    fi
                done
            fi

            # 显示禁用的规则（简要）
            if [ "$disabled_count" -gt 0 ]; then
                echo -e "${YELLOW}禁用的规则:${NC}"
                for rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$rule_file" ]; then
                        if read_rule_file "$rule_file" && [ "$ENABLED" = "false" ]; then
                            # 根据规则角色使用不同的字段
                            if [ "$RULE_ROLE" = "2" ]; then
                                # 落地服务器使用FORWARD_TARGET
                                local target_host="${FORWARD_TARGET%:*}"
                                local target_port="${FORWARD_TARGET##*:}"
                                local display_target=$(smart_display_target "$target_host")
                                echo -e "  • ${GRAY}$RULE_NAME${NC}: $LISTEN_PORT → $display_target:$target_port (已禁用)"
                            else
                                # 中转服务器使用REMOTE_HOST
                                local display_target=$(smart_display_target "$REMOTE_HOST")
                                local through_display="${THROUGH_IP:-::}"
                                echo -e "  • ${GRAY}$RULE_NAME${NC}: $LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT (已禁用)"
                            fi
                        fi
                    fi
                done
            fi
        else
            echo -e "配置模式: ${BLUE}暂无配置${NC}"
        fi
        echo ""

        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 一键导出/导入配置"
        echo -e "${GREEN}2.${NC} 添加新配置"
        echo -e "${GREEN}3.${NC} 删除配置"
        echo -e "${GREEN}4.${NC} 启用/禁用中转规则"
        echo -e "${BLUE}5.${NC} 负载均衡管理"
        echo -e "${YELLOW}6.${NC} 开启/关闭 MPTCP"
        echo -e "${CYAN}7.${NC} 开启/关闭 Proxy Protocol"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo ""

        read -p "请输入选择 [0-7]: " choice
        echo ""

        case $choice in
            1)
                # 一键导出/导入配置管理
                while true; do
                    clear
                    echo -e "${GREEN}=== 配置文件管理 ===${NC}"
                    echo ""
                    echo "请选择操作:"
                    echo -e "${GREEN}1.${NC} 导出配置包(包含查看配置)"
                    echo -e "${GREEN}2.${NC} 导入配置包"
                    echo -e "${GREEN}0.${NC} 返回上级菜单"
                    echo ""
                    read -p "请输入选择 [0-2]: " sub_choice
                    echo ""

                    case $sub_choice in
                        1)
                            export_config_with_view
                            ;;
                        2)
                            import_config_package
                            ;;
                        0)
                            break
                            ;;
                        *)
                            echo -e "${RED}无效选择，请重新输入${NC}"
                            read -p "按回车键继续..."
                            ;;
                    esac
                done
                ;;
            2)
                interactive_add_rule
                if [ $? -eq 0 ]; then
                    echo -e "${YELLOW}正在重启服务以应用新配置...${NC}"
                    service_restart
                fi
                read -p "按回车键继续..."
                ;;
            3)
                echo -e "${YELLOW}=== 删除配置 ===${NC}"
                echo ""
                if list_rules_with_info "management"; then
                    echo ""
                    read -p "请输入要删除的规则ID(多ID使用逗号,分隔): " rule_input

                    # 检查输入是否为空
                    if [ -z "$rule_input" ]; then
                        echo -e "${RED}错误: 请输入规则ID${NC}"
                    else
                        # 判断是单个ID还是多个ID
                        if [[ "$rule_input" == *","* ]]; then
                            # 多个ID，使用批量删除
                            batch_delete_rules "$rule_input"
                        else
                            # 单个ID，直接调用delete_rule（不跳过确认）
                            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                                delete_rule "$rule_input"
                            else
                                echo -e "${RED}无效的规则ID${NC}"
                            fi
                        fi

                        # 统一处理服务重启
                        if [ $? -eq 0 ]; then
                            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
                            service_restart
                        fi
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            4)
                echo -e "${YELLOW}=== 启用/禁用中转规则 ===${NC}"
                echo ""
                if list_rules_with_info "management"; then
                    echo ""
                    read -p "请输入要切换状态的规则ID: " rule_id
                    if [[ "$rule_id" =~ ^[0-9]+$ ]]; then
                        toggle_rule "$rule_id"
                        if [ $? -eq 0 ]; then
                            echo -e "${YELLOW}正在重启服务以应用状态更改...${NC}"
                            service_restart
                        fi
                    else
                        echo -e "${RED}无效的规则ID${NC}"
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            5)
                # 负载均衡管理
                load_balance_management_menu
                ;;
            6)
                # MPTCP管理
                mptcp_management_menu
                ;;
            7)
                # Proxy管理
                proxy_management_menu
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-7${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

#--- MPTCP管理功能 ---

# 检查MPTCP系统支持
check_mptcp_support() {
    # 检查内核版本
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)

    if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -le 6 ]); then
        return 1
    fi

    # 检查MPTCP是否启用
    if [ -f "/proc/sys/net/mptcp/enabled" ]; then
        local enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
        [ "$enabled" = "1" ]
    else
        return 1
    fi
}

# 启用MPTCP功能
enable_mptcp() {
    echo -e "${BLUE}正在启用MPTCP并进行配置...${NC}"
    echo ""

    # 检查并升级iproute2包
    echo -e "${YELLOW}步骤1: 检查并升级iproute2包...${NC}"
    upgrade_iproute2_for_mptcp

    # 创建sysctl配置文件启用MPTCP
    echo -e "${YELLOW}步骤2: 启用系统MPTCP...${NC}"
    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"

    # 创建完整的MPTCP配置文件
    cat > "$mptcp_conf" << EOF
# MPTCP基础配置
net.mptcp.enabled=1

# 强制使用内核路径管理器
net.mptcp.pm_type=0

# 优化反向路径过滤
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ MPTCP配置文件已创建: $mptcp_conf${NC}"

        # 立即应用配置
        if sysctl -p "$mptcp_conf" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ MPTCP已成功启用并保存生效${NC}"
        else
            echo -e "${YELLOW}配置文件已创建，但立即应用失败${NC}"
            echo -e "${YELLOW}请手动执行: sysctl -p $mptcp_conf${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法创建MPTCP配置文件${NC}"
        return 1
    fi

    # 优化MPTCP系统参数
    echo -e "${YELLOW}步骤3: 优化MPTCP系统参数...${NC}"

    # 强制使用内核路径管理器
    if sysctl -w net.mptcp.pm_type=0 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ 已切换到内核路径管理器${NC}"
    else
        echo -e "${YELLOW}⚠ 无法设置路径管理器类型${NC}"
    fi

    # 停止可能冲突的mptcpd服务
    if systemctl is-active mptcpd >/dev/null 2>&1; then
        echo -e "${YELLOW}检测到mptcpd服务，正在停止...${NC}"
        systemctl stop mptcpd 2>/dev/null || true
        systemctl disable mptcpd 2>/dev/null || true
        echo -e "${GREEN}✓ 已停止mptcpd服务${NC}"
    fi

    # 设置反向路径过滤（关键优化）
    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1
    echo -e "${GREEN}✓ 已优化反向路径过滤设置${NC}"

    # 设置MPTCP连接限制
    if /usr/bin/ip mptcp limits set subflows 8 add_addr_accepted 8 2>/dev/null; then
        echo -e "${GREEN}✓ MPTCP连接限制已设置为最大值 (subflows=8, add_addr_accepted=8)${NC}"
    else
        echo -e "${YELLOW}⚠ 无法设置MPTCP连接限制，使用默认值 (subflows=2, add_addr_accepted=0)${NC}"
    fi

    echo ""
    echo -e "${GREEN}✓ MPTCP基础配置完成！${NC}"
    echo -e "${BLUE}配置将自动加载${NC}"
    return 0
}

# 检查并升级iproute2包
upgrade_iproute2_for_mptcp() {
    # 获取当前版本
    local current_version=$(/usr/bin/ip -V 2>/dev/null | grep -oP 'iproute2-\K[^,\s]+' || echo "unknown")
    echo -e "${BLUE}当前iproute2版本: $current_version${NC}"

    # 检查MPTCP功能支持
    local mptcp_help_output=$(/usr/bin/ip mptcp help 2>&1)
    if echo "$mptcp_help_output" | grep -q "endpoint\|limits"; then
        echo -e "${GREEN}✓ 当前版本已支持MPTCP${NC}"
        return 0
    fi

    echo -e "${YELLOW}当前版本不支持MPTCP，开始升级...${NC}"

    # 使用包管理器升级
    echo -e "${BLUE}正在使用包管理器升级...${NC}"
    local apt_output
    apt_output=$(apt update 2>&1 && apt install -y iproute2 2>&1)

    # 检查升级结果
    local mptcp_help_output=$(/usr/bin/ip mptcp help 2>&1)
    if [ $? -eq 0 ] && echo "$mptcp_help_output" | grep -q "endpoint\|limits"; then
        echo -e "${GREEN}✓ 升级成功，MPTCP现在可用${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ 升级后仍不支持MPTCP${NC}"
        echo -e "${YELLOW}当前系统版本过低，请尝试手动更新iproute2${NC}"
        return 1
    fi
}

# 禁用MPTCP功能
disable_mptcp() {
    echo -e "${BLUE}正在禁用MPTCP并清理配置...${NC}"
    echo ""

    # 清理MPTCP端点
    echo -e "${YELLOW}步骤1: 清理MPTCP端点...${NC}"
    if /usr/bin/ip mptcp endpoint show >/dev/null 2>&1; then
        local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
        if [ -n "$endpoints_output" ]; then
            # 清理所有端点
            /usr/bin/ip mptcp endpoint flush 2>/dev/null
            echo -e "${GREEN}✓ 已清理所有MPTCP端点${NC}"
        else
            echo -e "${BLUE}  无MPTCP端点需要清理${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ ip mptcp命令不可用，跳过端点清理${NC}"
    fi

    # 禁用系统MPTCP
    echo -e "${YELLOW}步骤2: 禁用系统MPTCP...${NC}"
    if echo 0 > /proc/sys/net/mptcp/enabled 2>/dev/null; then
        echo -e "${GREEN}✓ MPTCP已立即禁用${NC}"
    else
        echo -e "${YELLOW}立即禁用MPTCP失败，但将删除配置文件${NC}"
    fi

    # 删除配置文件
    echo -e "${YELLOW}步骤3: 删除配置文件...${NC}"
    local mptcp_conf="/etc/sysctl.d/90-enable-MPTCP.conf"
    if [ -f "$mptcp_conf" ]; then
        if rm -f "$mptcp_conf" 2>/dev/null; then
            echo -e "${GREEN}✓ MPTCP配置文件已删除${NC}"
        else
            echo -e "${YELLOW}无法删除配置文件: $mptcp_conf${NC}"
            echo -e "${YELLOW}请手动删除以防止重启后自动启用${NC}"
        fi
    else
        echo -e "${BLUE}  无配置文件需要删除${NC}"
    fi

    echo ""
    echo -e "${GREEN}✓ MPTCP已完全禁用！${NC}"
    echo -e "${BLUE}重启后MPTCP将保持禁用状态,恢复TCP${NC}"
    return 0
}

# 获取MPTCP模式显示文本
get_mptcp_mode_display() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "关闭"
            ;;
        "send")
            echo "发送"
            ;;
        "accept")
            echo "接收"
            ;;
        "both")
            echo "双向"
            ;;
        *)
            echo "关闭"
            ;;
    esac
}

# 获取MPTCP模式颜色
get_mptcp_mode_color() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "${WHITE}"
            ;;
        "send")
            echo "${BLUE}"
            ;;
        "accept")
            echo "${YELLOW}"
            ;;
        "both")
            echo "${GREEN}"
            ;;
        *)
            echo "${WHITE}"
            ;;
    esac
}

# 获取网络接口详细信息
get_network_interfaces_detailed() {
    local interfaces_info=""

    # 获取所有网络接口
    for interface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo); do
        local ipv4_info=""
        local ipv6_info=""

        # 获取IPv4地址
        local ipv4_addrs=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP 'inet \K[^/]+/[0-9]+' | head -1)
        if [ -n "$ipv4_addrs" ]; then
            ipv4_info="$ipv4_addrs (IPv4)"
        else
            ipv4_info="未配置IPv4"
        fi

        # 获取IPv6地址（排除链路本地地址）
        local ipv6_addrs=$(ip -6 addr show "$interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+/[0-9]+' | grep -v '^fe80:' | head -1)
        if [ -n "$ipv6_addrs" ]; then
            ipv6_info="$ipv6_addrs (IPv6)"
        else
            ipv6_info="未配置IPv6"
        fi

        # 检查是否为VLAN接口
        local vlan_info=""
        if [[ "$interface" == *"."* ]]; then
            vlan_info=" (VLAN)"
        fi

        interfaces_info="${interfaces_info}  网卡 $interface: $ipv4_info | $ipv6_info$vlan_info\n"
    done

    echo -e "$interfaces_info"
}

# 获取MPTCP端点配置状态
get_mptcp_endpoints_status() {
    local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)
    local endpoint_count=0
    local endpoints_info=""

    if [ -n "$endpoints_output" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                endpoint_count=$((endpoint_count + 1))
                # 解析端点信息
                local id=$(echo "$line" | grep -oP 'id \K[0-9]+' || echo "")
                local addr=$(echo "$line" | grep -oP '^[^ ]+' || echo "")
                local dev=$(echo "$line" | grep -oP 'dev \K[^ ]+' || echo "")
                # 解析MPTCP端点类型：脚本支持的三种模式
                local flags=""
                if echo "$line" | grep -q "subflow.*fullmesh"; then
                    flags="[subflow fullmesh]"
                elif echo "$line" | grep -q "subflow.*backup"; then
                    flags="[subflow backup]"
                elif echo "$line" | grep -q "signal"; then
                    flags="[signal]"
                else
                    flags="[unknown]"
                fi

                if [ -n "$addr" ]; then
                    endpoints_info="${endpoints_info}  ID $id: $addr dev $dev $flags\n"
                fi
            fi
        done <<< "$endpoints_output"
    fi

    echo -e "${BLUE}MPTCP端点配置:${NC}"
    if [ $endpoint_count -gt 0 ]; then
        echo -e "$endpoints_info"
    else
        echo -e "  ${YELLOW}暂无MPTCP端点配置${NC}"
    fi

    return $endpoint_count
}

# 统计MPTCP连接数量
get_mptcp_connections_stats() {
    local ss_output=$(ss -M 2>/dev/null)
    local mptcp_connections=0
    local subflows=0

    if [ -n "$ss_output" ]; then
        # 统计已建立的连接数 (grep -c 总是返回数字，包括0)
        mptcp_connections=$(echo "$ss_output" | grep -c ESTAB 2>/dev/null)

        # 统计子流数量 (总行数减1，最少为0)
        local total_lines=$(echo "$ss_output" | wc -l)
        subflows=$(( total_lines > 1 ? total_lines - 1 : 0 ))
    fi

    # 输出统计结果
    if [ "$mptcp_connections" -eq 0 ] && [ "$subflows" -eq 0 ]; then
        echo "活跃连接: 0个 | 子流: 0个 (无连接时为0正常现象)"
    else
        echo "活跃连接: ${mptcp_connections}个 | 子流: ${subflows}个"
    fi
}

# MPTCP管理主菜单
mptcp_management_menu() {
    # 初始化MPTCP字段（确保向后兼容）
    init_mptcp_fields

    while true; do
        clear
        echo -e "${GREEN}=== MPTCP 管理 ===${NC}"
        echo ""

        # 首先检查系统支持
        if ! check_mptcp_support; then
            local kernel_version=$(uname -r)
            local kernel_major=$(echo $kernel_version | cut -d. -f1)
            local kernel_minor=$(echo $kernel_version | cut -d. -f2)

            echo -e "${RED}系统不支持MPTCP或未启用${NC}"
            echo ""
            echo -e "${YELLOW}MPTCP要求：${NC}"
            echo -e "  • Linux内核版本 > 5.6"
            echo -e "  • net.mptcp.enabled=1"
            echo ""

            echo -e "${BLUE}当前内核版本: ${GREEN}$kernel_version${NC}"

            # 检查内核版本支持情况
            if [ "$kernel_major" -lt 5 ] || ([ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -le 6 ]); then
                echo -e "${RED}✗ 内核版本不支持MPTCP${NC}(需要 > 5.6)"
            else
                echo -e "${GREEN}✓ 内核版本支持MPTCP${NC}"
            fi

            # 检查MPTCP启用状态
            if [ -f "/proc/sys/net/mptcp/enabled" ]; then
                local enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
                if [ "$enabled" = "1" ]; then
                    echo -e "${GREEN}✓ MPTCP已启用${NC}(net.mptcp.enabled=$enabled)"
                else
                    echo -e "${RED}✗ MPTCP未启用${NC}(net.mptcp.enabled=$enabled，需要为1)"
                fi
            else
                echo -e "${RED}✗ 系统不支持MPTCP${NC}(/proc/sys/net/mptcp/enabled 不存在)"
            fi

            echo ""
            read -p "是否尝试启用MPTCP? [y/N]: " enable_choice
            if [[ "$enable_choice" =~ ^[Yy]$ ]]; then
                enable_mptcp
            fi
            echo ""
            read -p "按回车键返回..."
            return
        fi

        # 显示详细的系统MPTCP状态
        local current_status=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null)
        local config_file="/etc/sysctl.d/90-enable-MPTCP.conf"

        echo -e "${GREEN}✓ 系统支持MPTCP${NC}(net.mptcp.enabled=$current_status)"

        if [ "$current_status" = "1" ]; then
            if [ -f "$config_file" ]; then
                echo -e "${GREEN}✓ 系统已开启MPTCP${NC}(MPTCP配置已设置)"
            else
                echo -e "${YELLOW}⚠ 系统已开启MPTCP${NC}(临时开启，重启后可能失效)"
                echo ""
                read -p "是否保存为配置文件重启依旧生效？[y/N]: " save_config
                if [[ "$save_config" =~ ^[Yy]$ ]]; then
                    if echo "net.mptcp.enabled=1" > "$config_file" 2>/dev/null; then
                        echo -e "${GREEN}✓ MPTCP配置已保存: $config_file${NC}"

                        # 立即应用配置
                        if sysctl -p "$config_file" >/dev/null 2>&1; then
                            echo -e "${GREEN}✓ 配置已立即生效，重启后自动加载${NC}"
                        else
                            echo -e "${YELLOW}配置文件已保存，但立即应用失败${NC}"
                            echo -e "${BLUE}手动应用配置: sysctl -p $config_file${NC}"
                        fi
                        echo ""
                        read -p "按回车键刷新状态显示..."
                        continue  # 重新开始循环，刷新状态显示
                    else
                        echo -e "${RED}✗ 保存MPTCP配置失败${NC}"
                        echo -e "${YELLOW}请手动执行: echo 'net.mptcp.enabled=1' > $config_file${NC}"
                    fi
                fi
            fi
        else
            echo -e "${RED}✗ 系统未开启MPTCP${NC}(当前为普通TCP模式)"
        fi
        echo ""

        # 显示网络环境状态
        echo -e "${BLUE}网络环境状态:${NC}"
        get_network_interfaces_detailed
        echo ""

        # 显示MPTCP端点配置和连接统计
        get_mptcp_endpoints_status
        local connections_stats=$(get_mptcp_connections_stats)
        echo -e "${BLUE}MPTCP连接统计:${NC}"
        echo -e "  $connections_stats"
        echo ""

        # 显示规则列表和MPTCP状态
        if ! list_rules_with_info "mptcp"; then
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${RED}规则ID 0: 关闭系统MPTCP，回退普通TCP模式${NC}"
        echo -e "${BLUE}输入 add: 添加MPTCP端点 | del: 删除MPTCP端点 | look: 查看MPTCP详细状态${NC}"
        read -p "请输入要配置的规则ID(多ID使用逗号,分隔，0为关闭系统MPTCP): " rule_input
        if [ -z "$rule_input" ]; then
            return
        fi

        # 处理特殊命令
        case "$rule_input" in
            "add")
                add_mptcp_endpoint_interactive
                read -p "按回车键继续..."
                continue
                ;;
            "del")
                delete_mptcp_endpoint_interactive
                read -p "按回车键继续..."
                continue
                ;;
            "look")
                show_mptcp_detailed_status
                read -p "按回车键继续..."
                continue
                ;;
        esac

        # 规则ID 0的特殊处理：直接关闭系统MPTCP
        if [ "$rule_input" = "0" ]; then
            echo ""
            echo -e "${YELLOW}确认关闭系统MPTCP？这将影响所有MPTCP连接。${NC}"
            read -p "继续? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                set_mptcp_mode "0" ""
            fi
            read -p "按回车键继续..."
            continue
        fi

        # 显示MPTCP模式选择
        echo ""
        echo -e "${BLUE}请选择新的 MPTCP 模式:${NC}"
        echo -e "${WHITE}1.${NC} off (关闭)"
        echo -e "${BLUE}2.${NC} 仅发送"
        echo -e "${YELLOW}3.${NC} 仅接收"
        echo -e "${GREEN}4.${NC} 双向(发送+接收)"
        echo ""

        read -p "请选择MPTCP模式 [1-4]: " mode_choice
        if [ -z "$mode_choice" ]; then
            continue
        fi

        # 判断是单个ID还是多个ID
        if [[ "$rule_input" == *","* ]]; then
            # 多个ID，使用批量设置
            batch_set_mptcp_mode "$rule_input" "$mode_choice"
        else
            # 单个ID，直接设置
            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                set_mptcp_mode "$rule_input" "$mode_choice"
            else
                echo -e "${RED}无效的规则ID${NC}"
            fi
        fi
        read -p "按回车键继续..."
    done
}

# 批量设置MPTCP模式
batch_set_mptcp_mode() {
    local rule_ids="$1"
    local mode_choice="$2"

    # 使用验证函数
    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    # 检查是否有无效ID
    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    # 检查是否有有效ID
    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    # 转换为数组
    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    # 显示所有要设置的规则信息
    echo -e "${YELLOW}即将为以下规则设置MPTCP模式:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
        fi
    done
    echo ""

    # 批量确认设置
    read -p "确认为以上 $valid_count 个规则设置MPTCP模式？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local success_count=0
        # 循环设置每个规则
        for id in "${valid_ids_array[@]}"; do
            if set_mptcp_mode "$id" "$mode_choice" "batch"; then
                success_count=$((success_count + 1))
            fi
        done

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ 成功设置 $success_count 个规则的MPTCP模式${NC}"
            # 重启服务以应用更改
            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，MPTCP配置已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗ 没有成功设置任何规则${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}操作已取消${NC}"
        return 1
    fi
}

# 设置规则的MPTCP模式
set_mptcp_mode() {
    local rule_id="$1"
    local mode_choice="$2"
    local batch_mode="$3"  # 批量模式标志

    # 特殊处理规则ID 0：关闭系统MPTCP
    if [ "$rule_id" = "0" ]; then
        echo -e "${YELLOW}正在关闭系统MPTCP...${NC}"
        disable_mptcp
        echo -e "${GREEN}✓ 系统MPTCP已关闭，所有连接将使用普通TCP模式${NC}"
        return 0
    fi

    # 验证规则ID
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    # 读取规则信息
    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}错误: 读取规则文件失败${NC}"
        return 1
    fi

    # 转换模式选择为模式值
    local new_mode
    case "$mode_choice" in
        "1")
            new_mode="off"
            ;;
        "2")
            new_mode="send"
            ;;
        "3")
            new_mode="accept"
            ;;
        "4")
            new_mode="both"
            ;;
        *)
            echo -e "${RED}无效的模式选择${NC}"
            return 1
            ;;
    esac

    local mode_display=$(get_mptcp_mode_display "$new_mode")
    local mode_color=$(get_mptcp_mode_color "$new_mode")

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在为规则 '$RULE_NAME' 设置MPTCP模式为: ${mode_color}$mode_display${NC}"
    fi

    # 更新规则文件中的MPTCP_MODE字段
    local temp_file="${rule_file}.tmp.$$"

    if grep -q "^MPTCP_MODE=" "$rule_file"; then
        # 更新现有的MPTCP_MODE字段
        grep -v "^MPTCP_MODE=" "$rule_file" > "$temp_file"
        echo "MPTCP_MODE=\"$new_mode\"" >> "$temp_file"
        mv "$temp_file" "$rule_file"
    else
        # 添加新的MPTCP_MODE字段
        echo "MPTCP_MODE=\"$new_mode\"" >> "$rule_file"
    fi

    if [ $? -eq 0 ]; then
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${GREEN}✓ MPTCP模式已更新为: ${mode_color}$mode_display${NC}"
        fi
        restart_and_confirm "MPTCP配置" "$batch_mode"
        return $?
    else
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${RED}✗ 更新MPTCP模式失败${NC}"
        fi
        return 1
    fi
}



# 初始化所有规则文件的MPTCP字段（确保向后兼容）
init_mptcp_fields() {
    init_rule_field "MPTCP_MODE" "off"
}

# 添加MPTCP端点
add_mptcp_endpoint_interactive() {
    echo -e "${GREEN}=== 添加MPTCP端点 ===${NC}"
    echo ""

    # 显示当前MPTCP端点
    echo -e "${BLUE}当前MPTCP端点:${NC}"
    get_mptcp_endpoints_status
    echo ""

    # 获取所有网络接口信息
    local interfaces=()
    local interface_names=()
    local interface_count=0

    # 收集网络接口信息
    for interface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo); do
        local ipv4_addrs=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP 'inet \K[^/]+' | tr '\n' ' ')
        local ipv6_addrs=$(ip -6 addr show "$interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80:' | tr '\n' ' ')

        # 只显示有IP地址的接口
        if [ -n "$ipv4_addrs" ] || [ -n "$ipv6_addrs" ]; then
            interface_count=$((interface_count + 1))
            interfaces+=("$interface")

            # 构建显示信息
            local display_info="$interface: "
            if [ -n "$ipv4_addrs" ]; then
                display_info="${display_info}${ipv4_addrs}(IPv4)"
            else
                display_info="${display_info}未配置IPv4"
            fi

            display_info="${display_info} | "

            if [ -n "$ipv6_addrs" ]; then
                display_info="${display_info}${ipv6_addrs}(IPv6)"
            else
                display_info="${display_info}未配置IPv6"
            fi

            interface_names+=("$display_info")
        fi
    done

    if [ $interface_count -eq 0 ]; then
        echo -e "${RED}未找到配置IP地址的网络接口${NC}"
        return 1
    fi

    # 显示网络接口列表
    echo -e "${BLUE}当前网络接口:${NC}"
    for i in $(seq 0 $((interface_count - 1))); do
        echo -e "${GREEN}$((i + 1)).${NC} ${interface_names[$i]}"
    done
    echo ""

    # 选择网络接口
    read -p "请选择网卡 [1-$interface_count]: " interface_choice
    if [[ ! "$interface_choice" =~ ^[0-9]+$ ]] || [ "$interface_choice" -lt 1 ] || [ "$interface_choice" -gt $interface_count ]; then
        echo -e "${RED}无效的选择${NC}"
        return 1
    fi

    local selected_interface="${interfaces[$((interface_choice - 1))]}"
    echo -e "${BLUE}已选择网卡: $selected_interface${NC}"
    echo ""

    # 获取选中网卡的IP地址列表
    local selected_ips=()
    local ip_display=()
    local ip_count=0

    # 获取IPv4地址
    local ipv4_list=$(ip -4 addr show "$selected_interface" 2>/dev/null | grep -oP 'inet \K[^/]+')
    if [ -n "$ipv4_list" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                ip_count=$((ip_count + 1))
                selected_ips+=("$ip")
                ip_display+=("$ip (IPv4)")
            fi
        done <<< "$ipv4_list"
    fi

    # 获取IPv6地址
    local ipv6_list=$(ip -6 addr show "$selected_interface" 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80:')
    if [ -n "$ipv6_list" ]; then
        while IFS= read -r ip; do
            if [ -n "$ip" ]; then
                ip_count=$((ip_count + 1))
                selected_ips+=("$ip")
                ip_display+=("$ip (IPv6)")
            fi
        done <<< "$ipv6_list"
    fi

    if [ $ip_count -eq 0 ]; then
        echo -e "${RED}选中的网卡没有可用的IP地址${NC}"
        return 1
    fi

    # 显示IP地址列表
    echo -e "${BLUE}${selected_interface} 的可用IP地址:${NC}"
    for i in $(seq 0 $((ip_count - 1))); do
        echo -e "${GREEN}$((i + 1)).${NC} ${ip_display[$i]}"
    done
    echo ""

    # 选择IP地址
    read -p "请选择IP地址(回车默认全选): " ip_choice

    local selected_ip_list=()
    if [ -z "$ip_choice" ]; then
        # 默认全选
        selected_ip_list=("${selected_ips[@]}")
        echo -e "${BLUE}已选择全部IP地址${NC}"
    else
        if [[ ! "$ip_choice" =~ ^[0-9]+$ ]] || [ "$ip_choice" -lt 1 ] || [ "$ip_choice" -gt $ip_count ]; then
            echo -e "${RED}无效的选择${NC}"
            return 1
        fi
        selected_ip_list=("${selected_ips[$((ip_choice - 1))]}")
        echo -e "${BLUE}已选择IP地址: ${selected_ips[$((ip_choice - 1))]}${NC}"
    fi
    echo ""

    # 选择端点类型
    echo ""
    echo -e "${BLUE}请选择MPTCP端点类型:${NC}"
    echo ""
    echo -e "${YELLOW}建议:${NC}"
    echo -e "  • 中转机/客户端: 选择 subflow fullmesh"
    echo -e "  • 落地机/服务端: 选择 signal (可选)"
    echo -e "  • 备用路径: 选择 subflow backup (仅在主路径故障时使用)"
    echo ""
    echo -e "${GREEN}1.${NC} subflow fullmesh (客户端模式 - 全网格连接)"
    echo -e "${BLUE}2.${NC} signal (服务端模式 - 通告地址给客户端)"
    echo -e "${YELLOW}3.${NC} subflow backup (备用模式)"
    echo ""

    read -p "请选择端点类型(回车默认 1) [1-3]: " type_choice

    # 设置默认值
    if [ -z "$type_choice" ]; then
        type_choice="1"
    fi

    local endpoint_type
    local type_description
    case "$type_choice" in
        "1")
            endpoint_type="subflow fullmesh"
            type_description="subflow fullmesh (全网格模式)"
            ;;
        "2")
            endpoint_type="signal"
            type_description="signal (服务端模式)"
            ;;
        "3")
            endpoint_type="subflow backup"
            type_description="subflow backup (备用模式)"
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入${NC}"
            return 1
            ;;
    esac
    # 批量添加MPTCP端点
    echo -e "${YELLOW}正在添加MPTCP端点...${NC}"
    local success_count=0
    local total_count=${#selected_ip_list[@]}

    for ip_address in "${selected_ip_list[@]}"; do
        echo -e "${BLUE}执行命令: /usr/bin/ip mptcp endpoint add $ip_address dev $selected_interface $endpoint_type${NC}"

        local error_output
        error_output=$(/usr/bin/ip mptcp endpoint add "$ip_address" dev "$selected_interface" $endpoint_type 2>&1)
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✓ MPTCP端点添加成功: $ip_address${NC}"
            success_count=$((success_count + 1))
        else
            echo -e "${RED}✗ MPTCP端点添加失败: $ip_address${NC}"
            echo -e "${RED}错误信息: $error_output${NC}"
        fi
    done

    echo ""
    echo -e "${BLUE}添加结果: 成功 $success_count/$total_count${NC}"
    echo -e "${BLUE}网络接口: $selected_interface${NC}"
    echo -e "${BLUE}端点模式: $type_description${NC}"

    if [ $success_count -gt 0 ]; then
        # 显示更新后的端点列表
        echo ""
        echo -e "${BLUE}更新后的MPTCP端点:${NC}"
        get_mptcp_endpoints_status
    else
        echo -e "${YELLOW}可能的原因:${NC}"
        echo -e "  • 系统过低导致iproute2版本不支持MPTCP"
        echo -e "  • IP地址已存在"
        echo -e "  • 网络接口配置问题"
    fi
}

# 删除MPTCP端点
delete_mptcp_endpoint_interactive() {
    echo -e "${GREEN}=== 删除MPTCP端点 ===${NC}"
    echo ""

    # 显示当前MPTCP端点
    echo -e "${BLUE}当前MPTCP端点:${NC}"
    local endpoints_output=$(/usr/bin/ip mptcp endpoint show 2>/dev/null)

    if [ -z "$endpoints_output" ]; then
        echo -e "${YELLOW}暂无MPTCP端点配置${NC}"
        return 0
    fi

    local endpoint_count=0
    local endpoints_list=()

    while IFS= read -r line; do
        if [ -n "$line" ]; then
            endpoint_count=$((endpoint_count + 1))
            endpoints_list+=("$line")

            # 解析端点信息
            local id=$(echo "$line" | grep -oP 'id \K[0-9]+' || echo "")
            local addr=$(echo "$line" | grep -oP '^[^ ]+' || echo "")
            local dev=$(echo "$line" | grep -oP 'dev \K[^ ]+' || echo "")
            # 解析MPTCP端点类型：脚本支持的三种模式
            local flags=""
            if echo "$line" | grep -q "subflow.*fullmesh"; then
                flags="[subflow fullmesh]"
            elif echo "$line" | grep -q "subflow.*backup"; then
                flags="[subflow backup]"
            elif echo "$line" | grep -q "signal"; then
                flags="[signal]"
            else
                flags="[unknown]"
            fi

            echo -e "  ${endpoint_count}. ID $id: $addr dev $dev $flags"
        fi
    done <<< "$endpoints_output"

    if [ $endpoint_count -eq 0 ]; then
        echo -e "${YELLOW}暂无MPTCP端点配置${NC}"
        return 0
    fi

    echo ""
    read -p "请选择要删除的端点编号 [1-$endpoint_count]: " choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt $endpoint_count ]; then
        echo -e "${RED}无效的选择${NC}"
        return 1
    fi

    # 获取选中的端点信息
    local selected_line="${endpoints_list[$((choice-1))]}"
    local endpoint_id=$(echo "$selected_line" | grep -oP 'id \K[0-9]+' || echo "")
    local endpoint_addr=$(echo "$selected_line" | grep -oP '^[^ ]+' || echo "")

    echo ""
    echo -e "${YELLOW}确认删除MPTCP端点:${NC}"
    echo -e "  ID: $endpoint_id"
    echo -e "  地址: $endpoint_addr"
    read -p "继续删除? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}正在删除MPTCP端点...${NC}"
        if /usr/bin/ip mptcp endpoint delete id "$endpoint_id" 2>/dev/null; then
            echo -e "${GREEN}✓ MPTCP端点删除成功${NC}"

            # 显示更新后的端点列表
            echo ""
            echo -e "${BLUE}更新后的MPTCP端点:${NC}"
            get_mptcp_endpoints_status
        else
            echo -e "${RED}✗ MPTCP端点删除失败${NC}"
            return 1
        fi
    else
        echo -e "${BLUE}已取消删除操作${NC}"
    fi
}

# 显示MPTCP详细状态信息
show_mptcp_detailed_status() {
    echo -e "${GREEN}=== MPTCP详细状态 ===${NC}"
    echo ""

    # 系统MPTCP状态
    echo -e "${BLUE}系统MPTCP状态:${NC}"
    local mptcp_enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null || echo "0")
    if [ "$mptcp_enabled" = "1" ]; then
        echo -e "  ✓ MPTCP已启用 (net.mptcp.enabled=$mptcp_enabled)"
    else
        echo -e "  ✗ MPTCP未启用 (net.mptcp.enabled=$mptcp_enabled)"
    fi
    echo ""

    # MPTCP连接限制
    echo -e "${BLUE}MPTCP连接限制:${NC}"
    local limits_output=$(/usr/bin/ip mptcp limits show 2>/dev/null)
    if [ -n "$limits_output" ]; then
        echo "  $limits_output"
    else
        echo -e "  ${YELLOW}无法获取连接限制信息${NC}"
    fi
    echo ""

    # 网络接口状态
    echo -e "${BLUE}网络接口状态:${NC}"
    get_network_interfaces_detailed
    echo ""

    # MPTCP端点配置
    get_mptcp_endpoints_status
    echo ""

    # MPTCP连接统计
    echo -e "${BLUE}MPTCP连接统计:${NC}"
    local connections_stats=$(get_mptcp_connections_stats)
    echo -e "  $connections_stats"
    echo ""

    # 活跃MPTCP连接详情
    echo -e "${BLUE}活跃MPTCP连接详情:${NC}"
    local mptcp_connections=$(ss -M 2>/dev/null)
    if [ -n "$mptcp_connections" ] && [ "$(echo "$mptcp_connections" | wc -l)" -gt 1 ]; then
        echo "$mptcp_connections"
    else
        echo -e "  ${YELLOW}暂无活跃MPTCP连接${NC}"
    fi
    echo ""

    # 实时MPTCP事件监控
    echo -e "${BLUE}实时MPTCP事件监控:${NC}"
    echo -e "${YELLOW}正在启动实时监控，按 Ctrl+C 退出...${NC}"
    echo ""
    ip mptcp monitor || echo -e "  ${YELLOW}MPTCP事件监控不可用${NC}"
}
#--- Proxy管理功能 ---

# 获取Proxy模式显示文本
get_proxy_mode_display() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "关闭"
            ;;
        "v1_send")
            echo "v1发送"
            ;;
        "v1_accept")
            echo "v1接收"
            ;;
        "v1_both")
            echo "v1双向"
            ;;
        "v2_send")
            echo "v2发送"
            ;;
        "v2_accept")
            echo "v2接收"
            ;;
        "v2_both")
            echo "v2双向"
            ;;
        *)
            echo "关闭"
            ;;
    esac
}

# 获取Proxy模式颜色
get_proxy_mode_color() {
    local mode="$1"
    case "$mode" in
        "off")
            echo "${WHITE}"
            ;;
        "v1_send"|"v2_send")
            echo "${BLUE}"
            ;;
        "v1_accept"|"v2_accept")
            echo "${YELLOW}"
            ;;
        "v1_both"|"v2_both")
            echo "${GREEN}"
            ;;
        *)
            echo "${WHITE}"
            ;;
    esac
}

# 初始化所有规则文件的Proxy字段（确保向后兼容）
init_proxy_fields() {
    init_rule_field "PROXY_MODE" "off"
}

# Proxy管理主菜单
proxy_management_menu() {
    # 初始化Proxy字段（确保向后兼容）
    init_proxy_fields

    while true; do
        clear
        echo -e "${GREEN}=== Proxy Protocol 管理 ===${NC}"
        echo ""

        # 显示规则列表和Proxy状态
        if ! list_rules_with_info "proxy"; then
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        read -p "请输入要配置的规则ID(多ID使用逗号,分隔): " rule_input
        if [ -z "$rule_input" ]; then
            return
        fi



        # 显示Proxy协议版本选择
        echo ""
        echo -e "${BLUE}请选择 Proxy 协议版本:${NC}"
        echo -e "${WHITE}1.${NC} off (关闭)"
        echo -e "${BLUE}2.${NC} 协议v1"
        echo -e "${GREEN}3.${NC} 协议v2"
        echo ""

        read -p "请选择协议版本（回车默认v2） [1-3]: " version_choice
        if [ -z "$version_choice" ]; then
            version_choice="3"  # 默认选择v2
        fi

        # 如果选择关闭，直接设置
        if [ "$version_choice" = "1" ]; then
            # 判断是单个ID还是多个ID
            if [[ "$rule_input" == *","* ]]; then
                batch_set_proxy_mode "$rule_input" "off" ""
            else
                if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                    set_proxy_mode "$rule_input" "off" ""
                else
                    echo -e "${RED}无效的规则ID${NC}"
                fi
            fi
            read -p "按回车键继续..."
            continue
        fi

        # 选择方向
        echo ""
        echo -e "${BLUE}请选择 Proxy 方向:${NC}"
        echo -e "${BLUE}1.${NC} 仅发送 (send_proxy)"
        echo -e "${YELLOW}2.${NC} 仅接收 (accept_proxy)"
        echo -e "${GREEN}3.${NC} 双向 (send + accept)"
        echo ""

        read -p "请选择方向 [1-3]: " direction_choice
        if [ -z "$direction_choice" ]; then
            continue
        fi

        # 判断是单个ID还是多个ID
        if [[ "$rule_input" == *","* ]]; then
            # 多个ID，使用批量设置
            batch_set_proxy_mode "$rule_input" "$version_choice" "$direction_choice"
        else
            # 单个ID，直接设置
            if [[ "$rule_input" =~ ^[0-9]+$ ]]; then
                set_proxy_mode "$rule_input" "$version_choice" "$direction_choice"
            else
                echo -e "${RED}无效的规则ID${NC}"
            fi
        fi
        read -p "按回车键继续..."
    done
}




# 批量设置Proxy模式
batch_set_proxy_mode() {
    local rule_ids="$1"
    local version_choice="$2"
    local direction_choice="$3"

    # 使用验证函数
    local validation_result=$(validate_rule_ids "$rule_ids")
    IFS='|' read -r valid_count invalid_count valid_ids invalid_ids <<< "$validation_result"

    # 检查是否有无效ID
    if [ "$invalid_count" -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: $invalid_ids${NC}"
        return 1
    fi

    # 检查是否有有效ID
    if [ "$valid_count" -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    # 转换为数组
    local valid_ids_array
    IFS=' ' read -ra valid_ids_array <<< "$valid_ids"

    # 显示所有要设置的规则信息
    echo -e "${YELLOW}即将为以下规则设置Proxy模式:${NC}"
    echo ""
    for id in "${valid_ids_array[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC}"
        fi
    done
    echo ""

    # 批量确认设置
    read -p "确认为以上 $valid_count 个规则设置Proxy模式？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local success_count=0
        # 循环设置每个规则
        for id in "${valid_ids_array[@]}"; do
            if set_proxy_mode "$id" "$version_choice" "$direction_choice" "batch"; then
                success_count=$((success_count + 1))
            fi
        done

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ 成功设置 $success_count 个规则的Proxy模式${NC}"
            # 重启服务以应用更改
            echo -e "${YELLOW}正在重启服务以应用配置更改...${NC}"
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，Proxy配置已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗ 没有成功设置任何规则${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}操作已取消${NC}"
        return 1
    fi
}

# 设置规则的Proxy模式
set_proxy_mode() {
    local rule_id="$1"
    local version_choice="$2"
    local direction_choice="$3"
    local batch_mode="$4"  # 批量模式标志

    # 验证规则ID
    local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
    if [ ! -f "$rule_file" ]; then
        echo -e "${RED}错误: 规则 $rule_id 不存在${NC}"
        return 1
    fi

    # 读取规则信息
    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}错误: 读取规则文件失败${NC}"
        return 1
    fi

    # 处理关闭模式
    if [ "$version_choice" = "off" ]; then
        local new_mode="off"
        local mode_display=$(get_proxy_mode_display "$new_mode")
        local mode_color=$(get_proxy_mode_color "$new_mode")

        if [ "$batch_mode" != "batch" ]; then
            echo -e "${YELLOW}正在为规则 '$RULE_NAME' 关闭Proxy功能${NC}"
        fi

        # 更新规则文件
        update_proxy_mode_in_file "$rule_file" "$new_mode"

        if [ $? -eq 0 ]; then
            if [ "$batch_mode" != "batch" ]; then
                echo -e "${GREEN}✓ Proxy已关闭${NC}"
                restart_service_for_proxy
            fi
        fi
        return $?
    fi

    # 转换版本和方向选择为模式值
    local version=""
    case "$version_choice" in
        "2")
            version="v1"
            ;;
        "3")
            version="v2"
            ;;
        *)
            echo -e "${RED}无效的版本选择${NC}"
            return 1
            ;;
    esac

    local direction=""
    case "$direction_choice" in
        "1")
            direction="send"
            ;;
        "2")
            direction="accept"
            ;;
        "3")
            direction="both"
            ;;
        *)
            echo -e "${RED}无效的方向选择${NC}"
            return 1
            ;;
    esac

    local new_mode="${version}_${direction}"
    local mode_display=$(get_proxy_mode_display "$new_mode")
    local mode_color=$(get_proxy_mode_color "$new_mode")

    if [ "$batch_mode" != "batch" ]; then
        echo -e "${YELLOW}正在为规则 '$RULE_NAME' 设置Proxy模式为: ${mode_color}$mode_display${NC}"
    fi

    # 更新规则文件
    update_proxy_mode_in_file "$rule_file" "$new_mode"

    if [ $? -eq 0 ]; then
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${GREEN}✓ Proxy模式已更新为: ${mode_color}$mode_display${NC}"
            restart_service_for_proxy
        fi
        return 0
    else
        if [ "$batch_mode" != "batch" ]; then
            echo -e "${RED}✗ 更新Proxy模式失败${NC}"
        fi
        return 1
    fi
}

# 更新规则文件中的Proxy模式
update_proxy_mode_in_file() {
    local rule_file="$1"
    local new_mode="$2"
    local temp_file="${rule_file}.tmp.$$"

    if grep -q "^PROXY_MODE=" "$rule_file"; then
        # 更新现有的PROXY_MODE字段
        grep -v "^PROXY_MODE=" "$rule_file" > "$temp_file"
        echo "PROXY_MODE=\"$new_mode\"" >> "$temp_file"
        mv "$temp_file" "$rule_file"
    else
        # 添加新的PROXY_MODE字段
        echo "PROXY_MODE=\"$new_mode\"" >> "$rule_file"
    fi
}

# 重启服务以应用Proxy配置
restart_service_for_proxy() {
    echo -e "${YELLOW}正在重启服务以应用Proxy配置...${NC}"
    if service_restart; then
        echo -e "${GREEN}✓ 服务重启成功，Proxy配置已生效${NC}"
        return 0
    else
        echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
        return 1
    fi
}



# 负载均衡管理菜单
load_balance_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 负载均衡管理(按端口组管理) ===${NC}"
        echo ""

        # 检查是否有中转服务器规则
        if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无转发规则，请先创建转发规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        # 按端口分组收集中转服务器规则，只显示有多个服务器的端口组
        declare -A port_groups
        declare -A port_configs
        declare -A port_balance_modes
        declare -A port_weights
        declare -A port_failover_status

        # 收集所有中转服务器规则
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（使用第一个规则的配置作为基准）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_balance_modes[$port_key]="${BALANCE_MODE:-off}"
                        port_weights[$port_key]="$WEIGHTS"
                        port_failover_status[$port_key]="${FAILOVER_ENABLED:-false}"
                    fi

                    # 处理REMOTE_HOST中的多个地址
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 只显示有多个服务器的端口组
        local has_balance_groups=false
        echo -e "${GREEN}中转服务器:${NC}"

        for port_key in $(printf '%s\n' "${!port_groups[@]}" | sort -n); do
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            # 只显示有至少两台服务器的端口组
            if [ $target_count -gt 1 ]; then
                has_balance_groups=true

                local balance_mode="${port_balance_modes[$port_key]}"
                local balance_info=$(get_balance_info_display "${port_groups[$port_key]}" "$balance_mode")

                # 显示端口组标题
                echo -e "  ${BLUE}端口 $port_key${NC}: ${GREEN}${port_configs[$port_key]}${NC} [$balance_info] - $target_count个服务器"

                # 显示每个服务器及其权重
                for ((i=0; i<target_count; i++)); do
                    local target="${targets[i]}"

                    # 获取权重信息
                    local current_weight=1
                    local weights_str="${port_weights[$port_key]}"

                    if [ -n "$weights_str" ] && [[ "$weights_str" == *","* ]]; then
                        IFS=',' read -ra weight_array <<< "$weights_str"
                        current_weight="${weight_array[i]:-1}"
                    elif [ -n "$weights_str" ] && [[ "$weights_str" != *","* ]]; then
                        current_weight="$weights_str"
                    fi

                    # 计算权重百分比
                    local total_weight=0
                    if [ -n "$weights_str" ] && [[ "$weights_str" == *","* ]]; then
                        IFS=',' read -ra weight_array <<< "$weights_str"
                        for w in "${weight_array[@]}"; do
                            total_weight=$((total_weight + w))
                        done
                    else
                        total_weight=$((target_count * current_weight))
                    fi

                    local percentage
                    if [ "$total_weight" -gt 0 ]; then
                        if command -v bc >/dev/null 2>&1; then
                            percentage=$(echo "scale=1; $current_weight * 100 / $total_weight" | bc 2>/dev/null || echo "100.0")
                        else
                            percentage=$(awk "BEGIN {printf \"%.1f\", $current_weight * 100 / $total_weight}")
                        fi
                    else
                        percentage="100.0"
                    fi

                    # 构建故障转移状态信息
                    local failover_info=""
                    if [ "$balance_mode" != "off" ] && [ "${port_failover_status[$port_key]}" = "true" ]; then
                        local health_status_file="/etc/realm/health/health_status.conf"
                        local node_status="healthy"

                        if [ -f "$health_status_file" ]; then
                            local host_only=$(echo "$target" | cut -d':' -f1)
                            local health_key="*|${host_only}"
                            local found_status=$(grep "^.*|${host_only}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3 | head -1)
                            if [ "$found_status" = "failed" ]; then
                                node_status="failed"
                            fi
                        fi

                        case "$node_status" in
                            "healthy") failover_info=" ${GREEN}[健康]${NC}" ;;
                            "failed") failover_info=" ${RED}[故障]${NC}" ;;
                        esac
                    fi

                    # 显示服务器信息（只在负载均衡模式下显示权重）
                    if [ "$balance_mode" != "off" ]; then
                        echo -e "    ${BLUE}$((i+1)).${NC} $target ${GREEN}[权重: $current_weight]${NC} ${BLUE}($percentage%)${NC}$failover_info"
                    else
                        echo -e "    ${BLUE}$((i+1)).${NC} $target$failover_info"
                    fi
                done
                echo ""
            fi
        done

        if [ "$has_balance_groups" = false ]; then
            echo -e "${YELLOW}暂无符合条件的负载均衡组${NC}"
            echo -e "${BLUE}提示: 只显示单端口有至少两台服务器的中转规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 切换负载均衡模式"
        echo -e "${BLUE}2.${NC} 权重配置管理"
        echo -e "${YELLOW}3.${NC} 开启/关闭故障转移"
        echo -e "${RED}0.${NC} 返回上级菜单"
        echo ""

        read -p "请输入选择 [0-3]: " choice
        echo ""

        case $choice in
            1)
                # 切换负载均衡模式
                switch_balance_mode
                ;;
            2)
                # 权重配置管理
                weight_management_menu
                ;;
            3)
                # 开启/关闭故障转移
                toggle_failover_mode
                ;;
            0)
                # 返回上级菜单
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-3${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 切换负载均衡模式（按端口分组管理）
switch_balance_mode() {
    while true; do
        clear
        echo -e "${YELLOW}=== 切换负载均衡模式 ===${NC}"
        echo ""

        # 按端口分组收集中转服务器规则
        # 清空并重新初始化关联数组
        unset port_groups port_configs port_balance_modes
        declare -A port_groups
        declare -A port_configs
        declare -A port_balance_modes

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（使用第一个规则的配置作为基准）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_balance_modes[$port_key]="${BALANCE_MODE:-off}"
                    fi

                    # 正确处理REMOTE_HOST中可能包含多个地址的情况
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        # REMOTE_HOST包含多个地址，分别添加
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            # 检查是否已存在，避免重复添加
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        # REMOTE_HOST是单个地址
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        # 检查是否已存在，避免重复添加
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 显示端口组列表（只显示有多个目标服务器的端口组）
        local has_balance_rules=false
        declare -a rule_ports
        declare -a rule_names

        for port_key in "${!port_groups[@]}"; do
            # 计算目标服务器总数
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            # 只显示有多个目标服务器的端口组
            if [ "$target_count" -gt 1 ]; then
                if [ "$has_balance_rules" = false ]; then
                    echo "请选择要切换负载均衡模式的规则组 (仅显示多目标服务器的规则组):"
                    has_balance_rules=true
                fi

                # 使用数字ID
                local rule_number=$((${#rule_ports[@]} + 1))
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")

                local balance_mode="${port_balance_modes[$port_key]}"
                local balance_display=""
                case "$balance_mode" in
                    "roundrobin")
                        balance_display="${YELLOW}[轮询]${NC}"
                        ;;
                    "iphash")
                        balance_display="${BLUE}[IP哈希]${NC}"
                        ;;
                    *)
                        balance_display="${WHITE}[off]${NC}"
                        ;;
                esac

                echo -e "${GREEN}$rule_number.${NC} ${port_configs[$port_key]} (端口: $port_key) $balance_display - $target_count个目标服务器"
            fi
        done

        if [ "$has_balance_rules" = false ]; then
            echo -e "${YELLOW}暂无多目标服务器的规则组${NC}"
            echo -e "${BLUE}提示: 只有具有多个目标服务器的规则组才能配置负载均衡${NC}"
            echo ""
            echo -e "${BLUE}负载均衡的前提条件：${NC}"
            echo -e "${BLUE}  1. 规则类型为中转服务器${NC}"
            echo -e "${BLUE}  2. 有多个目标服务器（单规则多地址或多规则单地址）${NC}"
            echo ""
            echo -e "${YELLOW}如果您需要添加更多目标服务器：${NC}"
            echo -e "${BLUE}  请到 '转发配置管理' → '添加转发规则' 创建更多规则${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${WHITE}注意: 负载均衡模式将应用到选定端口组的所有相关规则${NC}"
        echo ""
        read -p "请输入规则编号 [1-${#rule_ports[@]}] (或按回车返回): " choice

        if [ -z "$choice" ]; then
            return
        fi

        # 验证数字输入
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#rule_ports[@]} ]; then
            echo -e "${RED}无效的规则编号${NC}"
            read -p "按回车键继续..."
            continue
        fi

        # 计算数组索引（从0开始）
        local selected_index=$((choice - 1))
        local selected_port="${rule_ports[$selected_index]}"
        local current_balance_mode="${port_balance_modes[$selected_port]}"

        echo ""
        echo -e "${GREEN}当前选择: ${port_configs[$selected_port]} (端口: $selected_port)${NC}"
        echo -e "${BLUE}当前负载均衡模式: $current_balance_mode${NC}"
        echo ""
        echo "请选择新的负载均衡模式:"
        echo -e "${GREEN}1.${NC} 关闭负载均衡（off）"
        echo -e "${YELLOW}2.${NC} 轮询 (roundrobin)"
        echo -e "${BLUE}3.${NC} IP哈希 (iphash)"
        echo ""

        read -p "请输入选择 [1-3]: " mode_choice

        local new_mode=""
        local mode_display=""
        case $mode_choice in
            1)
                new_mode="off"
                mode_display="关闭"
                ;;
            2)
                new_mode="roundrobin"
                mode_display="轮询"
                ;;
            3)
                new_mode="iphash"
                mode_display="IP哈希"
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                read -p "按回车键继续..."
                continue
                ;;
        esac

        # 更新选定端口组下所有相关规则的负载均衡模式
        local updated_count=0
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$selected_port" ]; then
                    sed -i "s/BALANCE_MODE=\".*\"/BALANCE_MODE=\"$new_mode\"/" "$rule_file"
                    updated_count=$((updated_count + 1))
                fi
            fi
        done

        if [ $updated_count -gt 0 ]; then
            echo -e "${GREEN}✓ 已将端口 $selected_port 的 $updated_count 个规则的负载均衡模式更新为: $mode_display${NC}"
            echo -e "${YELLOW}正在重启服务以应用更改...${NC}"

            # 重启realm服务
            if service_restart; then
                echo -e "${GREEN}✓ 服务重启成功，负载均衡模式已生效${NC}"
            else
                echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
            fi
        else
            echo -e "${RED}✗ 未找到相关规则文件${NC}"
        fi

        read -p "按回车键继续..."
    done
}

# 启用/禁用中转规则
toggle_target_server() {
    echo -e "${YELLOW}=== 启用/禁用中转规则 ===${NC}"
    echo ""

    # 显示所有中转服务器规则（支持规则级别的启用/禁用）
    local has_relay_rules=false
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_and_check_relay_rule "$rule_file"; then
                if [ "$has_relay_rules" = false ]; then
                    echo -e "${GREEN}中转服务器:${NC}"
                    has_relay_rules=true
                fi

                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                local display_target=$(smart_display_target "$REMOTE_HOST")
                local balance_mode="${BALANCE_MODE:-off}"
                local balance_info=$(get_balance_info_display "$REMOTE_HOST" "$balance_mode")

                if [ "$RULE_ROLE" = "2" ]; then
                    local display_ip="::"
                else
                    local display_ip="${NAT_LISTEN_IP:-::}"
                fi
                local through_display="${THROUGH_IP:-::}"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$RULE_NAME${NC} (${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info"
            fi
        fi
    done

    if [ "$has_relay_rules" = false ]; then
        echo -e "${YELLOW}没有配置中转服务器规则${NC}"
        echo -e "${BLUE}提示: 需要先创建中转服务器规则才能进行启用/禁用操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    echo ""
    read -p "请输入要配置的规则ID: " selected_rule_id

    if ! [[ "$selected_rule_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的规则ID${NC}"
        read -p "按回车键返回..."
        return
    fi

    local rule_file="${RULES_DIR}/rule-${selected_rule_id}.conf"

    if ! read_rule_file "$rule_file" || [ "$RULE_ROLE" != "1" ]; then
        echo -e "${RED}规则不存在或不是中转服务器规则${NC}"
        read -p "按回车键返回..."
        return
    fi

    echo ""
    echo -e "${BLUE}规则: $RULE_NAME${NC}"
    echo -e "${BLUE}当前状态: ${ENABLED}${NC}"

    # 检查是否为单规则多目标（包含逗号）
    if [[ "$REMOTE_HOST" == *","* ]]; then
        echo -e "${BLUE}操作类型: 单规则内目标服务器启用/禁用${NC}"
        echo -e "${BLUE}目标服务器列表:${NC}"

        IFS=',' read -ra targets <<< "$REMOTE_HOST"
        local target_states="${TARGET_STATES:-}"

        for i in "${!targets[@]}"; do
            local target="${targets[i]}"
            local is_enabled=$(is_target_enabled "$i" "$target_states")

            local status_color="${GREEN}"
            local status_text="启用"
            if [ "$is_enabled" = "false" ]; then
                status_color="${RED}"
                status_text="禁用"
            fi

            echo -e "${GREEN}$((i + 1)).${NC} $target:$REMOTE_PORT [${status_color}$status_text${NC}]"
        done

        echo ""
        read -p "请输入要切换状态的目标编号 [1-${#targets[@]}]: " target_choice

        if ! [[ "$target_choice" =~ ^[0-9]+$ ]] || [ "$target_choice" -lt 1 ] || [ "$target_choice" -gt ${#targets[@]} ]; then
            echo -e "${RED}无效选择${NC}"
            read -p "按回车键返回..."
            return
        fi

        local target_index=$((target_choice - 1))
        local state_key="target_${target_index}"
        local current_enabled=$(is_target_enabled "$target_index" "$target_states")

        # 切换状态
        local new_enabled="true"
        if [ "$current_enabled" = "true" ]; then
            new_enabled="false"
        fi

        # 更新TARGET_STATES
        local new_target_states=""
        if [ -z "$target_states" ]; then
            new_target_states="$state_key:$new_enabled"
        else
            if [[ "$target_states" == *"$state_key:"* ]]; then
                # 替换现有状态
                new_target_states=$(echo "$target_states" | sed "s/$state_key:[^,]*/$state_key:$new_enabled/g")
            else
                # 添加新状态
                new_target_states="$target_states,$state_key:$new_enabled"
            fi
        fi

        # 更新规则文件
        sed -i "s/TARGET_STATES=\".*\"/TARGET_STATES=\"$new_target_states\"/" "$rule_file"

        local target_name="${targets[$target_index]}"
        if [ "$new_enabled" = "true" ]; then
            echo -e "${GREEN}✓ 目标服务器 $target_name:$REMOTE_PORT 已启用${NC}"
        else
            echo -e "${YELLOW}✓ 目标服务器 $target_name:$REMOTE_PORT 已禁用${NC}"
        fi
    else
        # 单目标规则，切换整个规则的启用/禁用状态
        echo -e "${BLUE}操作类型: 整个规则启用/禁用${NC}"
        echo -e "${BLUE}目标: $REMOTE_HOST:$REMOTE_PORT${NC}"

        local current_status="$ENABLED"
        local new_status="false"
        local action_text="禁用"
        local color="${RED}"

        if [ "$current_status" != "true" ]; then
            new_status="true"
            action_text="启用"
            color="${GREEN}"
        fi

        echo ""
        read -p "确认要${action_text}此规则吗？(y/n): " confirm

        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 更新规则文件
            sed -i "s/ENABLED=\".*\"/ENABLED=\"$new_status\"/" "$rule_file"
            echo -e "${color}✓ 规则 $RULE_NAME 已${action_text}${NC}"
        else
            echo "操作已取消"
        fi
    fi

    echo -e "${YELLOW}正在重启服务以应用更改...${NC}"
    service_restart

    read -p "按回车键继续..."
}

# 交互式角色选择
interactive_role_selection() {
    echo -e "${YELLOW}=== Realm 中转加速配置向导 ===${NC}"
    echo ""
    echo "请选择本服务器的角色:"
    echo -e "${GREEN}[1]${NC} 中转服务器"
    echo -e "${GREEN}[2]${NC} 落地服务器 (双端Realm架构)"
    echo ""

    while true; do
        read -p "请输入数字 [1-2]: " ROLE
        case $ROLE in
            1)
                echo -e "${GREEN}已选择: 中转服务器${NC}"
                break
                ;;
            2)
                echo -e "${GREEN}已选择: 落地服务器 (双端Realm架构)${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1 或 2${NC}"
                ;;
        esac
    done
    echo ""
}

# 中转服务器交互配置
configure_nat_server() {
    echo -e "${YELLOW}=== 中转服务器配置(不了解入口出口一般回车默认即可) ===${NC}"
    echo ""

    # 配置监听端口
    while true; do
        read -p "请输入本地监听端口 (客户端连接的端口，nat机需使用分配的端口): " NAT_LISTEN_PORT
        if validate_port "$NAT_LISTEN_PORT"; then
            echo -e "${GREEN}监听端口设置为: $NAT_LISTEN_PORT${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字${NC}"
        fi
    done

    # 诊断端口占用
    check_port_usage "$NAT_LISTEN_PORT" "中转服务器监听"
    local port_status=$?

    # 如果端口被realm占用，跳过IP地址、协议、传输方式配置
    if [ $port_status -eq 1 ]; then
        echo -e "${BLUE}检测到端口已被realm占用，读取现有配置，直接进入出口服务器配置${NC}"
        echo ""

        # 读取现有同端口规则的配置
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$LISTEN_PORT" = "$NAT_LISTEN_PORT" ] && [ "$RULE_ROLE" = "1" ]; then
                    # 找到同端口的中转服务器规则，使用其配置
                    NAT_LISTEN_IP="${LISTEN_IP}"
                    NAT_THROUGH_IP="${THROUGH_IP:-::}"
                    SECURITY_LEVEL="${SECURITY_LEVEL}"
                    TLS_SERVER_NAME="${TLS_SERVER_NAME}"
                    TLS_CERT_PATH="${TLS_CERT_PATH}"
                    TLS_KEY_PATH="${TLS_KEY_PATH}"
                    WS_PATH="${WS_PATH}"
                    RULE_NOTE="${RULE_NOTE:-}"  # 复用现有备注
                    echo -e "${GREEN}已读取端口 $NAT_LISTEN_PORT 的现有配置${NC}"
                    break
                fi
            fi
        done

        # 直接跳转到远程服务器配置
    else
        # 清空可能残留的备注变量（新端口配置）
        RULE_NOTE=""
        echo ""

        while true; do
            read -p "自定义(指定)入口监听IP地址(客户端连接IP,回车默认全部监听 ::): " listen_ip_input

            if [ -z "$listen_ip_input" ]; then
                # 使用默认值：双栈监听
                NAT_LISTEN_IP="::"
                echo -e "${GREEN}使用默认监听IP: :: (全部监听)${NC}"
                break
            else
                # 验证自定义输入
                if validate_ip "$listen_ip_input"; then
                    NAT_LISTEN_IP="$listen_ip_input"
                    echo -e "${GREEN}监听IP设置为: $NAT_LISTEN_IP${NC}"
                    break
                else
                    echo -e "${RED}无效IP地址格式${NC}"
                    echo -e "${YELLOW}支持格式: 有效的IPv4或IPv6地址${NC}"
                    echo -e "${YELLOW}示例: 192.168.1.100 或 2001:db8::1 或 0.0.0.0 或 ::${NC}"
                fi
            fi
        done

        echo ""

        while true; do
            read -p "自定义(指定)出口IP地址(适用于中转多IP出口情况,回车默认全部监听 ::): " through_ip_input

            if [ -z "$through_ip_input" ]; then
                # 使用默认值：双栈监听
                NAT_THROUGH_IP="::"
                echo -e "${GREEN}使用默认出口IP: :: (全部监听)${NC}"
                break
            else
                # 验证自定义输入
                if validate_ip "$through_ip_input"; then
                    NAT_THROUGH_IP="$through_ip_input"
                    echo -e "${GREEN}出口IP设置为: $NAT_THROUGH_IP${NC}"
                    break
                else
                    echo -e "${RED}无效IP地址格式${NC}"
                    echo -e "${YELLOW}支持格式: 有效的IPv4或IPv6地址${NC}"
                    echo -e "${YELLOW}示例: 192.168.1.100 或 2001:db8::1 或 0.0.0.0 或 ::${NC}"
                fi
            fi
        done

        echo ""
    fi

    # 配置远程服务器
    echo -e "${YELLOW}=== 出口服务器信息配置 ===${NC}"
    echo ""
    
    while true; do
        read -p "出口服务器的IP地址或域名: " REMOTE_IP
        if [ -n "$REMOTE_IP" ]; then
            # 检查是否为有效的IP或域名格式
            if validate_ip "$REMOTE_IP" || [[ "$REMOTE_IP" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                echo -e "${RED}请输入有效的IP地址或域名${NC}"
            fi
        else
            echo -e "${RED}IP地址或域名不能为空${NC}"
        fi
    done

    while true; do
        read -p "出口服务器的监听端口: " REMOTE_PORT
        if validate_port "$REMOTE_PORT"; then
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字${NC}"
        fi
    done

    # 测试连通性
    echo -e "${YELLOW}正在测试与出口服务器的连通性...${NC}"
    if check_connectivity "$REMOTE_IP" "$REMOTE_PORT"; then
        echo -e "${GREEN}✓ 连接测试成功！${NC}"
    else
        echo -e "${RED}✗ 连接测试失败，请检查出口服务器是否已启动并确认IP和端口正确${NC}"

        # 检查是否为域名，给出DDNS特别提醒
        if ! validate_ip "$REMOTE_IP" && [[ "$REMOTE_IP" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "${YELLOW}检测到您使用的是域名地址，如果是DDNS域名：${NC}"
            echo -e "${YELLOW}确认域名和端口正确后，直接继续配置无需担心${NC}"
            echo -e "${YELLOW}DDNS域名无法进行连通性测试${NC}"
        fi

        read -p "是否继续配置？(y/n): " continue_config
        if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
            echo "配置已取消"
            exit 1
        fi
    fi

    # 如果端口被realm占用，跳过协议和传输配置
    if [ $port_status -eq 1 ]; then
        # 跳过协议和传输配置，直接进入规则创建
        echo -e "${BLUE}使用默认配置完成设置${NC}"
    else
    # 传输模式选择
    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} WebSocket (ws)"
    echo -e "${GREEN}[3]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[4]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (自签证书)"
    echo -e "${GREEN}[6]${NC} TLS+WebSocket (CA证书)"
    echo ""

    while true; do
        read -p "请输入选择 [1-6]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="ws"
                echo -e "${GREEN}已选择: WebSocket${NC}"

                # WebSocket路径配置
                echo ""
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            4)
                SECURITY_LEVEL="tls_ca"
                echo -e "${GREEN}已选择: TLS CA证书${NC}"

                # 证书路径配置
                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME
                echo -e "${GREEN}TLS配置完成${NC}"
                break
                ;;
            5)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"

                # WebSocket路径配置
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            6)
                SECURITY_LEVEL="ws_tls_ca"
                echo -e "${GREEN}已选择: TLS+WebSocket CA证书${NC}"

                # 证书路径配置
                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME

                # WebSocket路径配置
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}TLS+WebSocket配置完成${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                ;;
        esac
    done

    fi  # 结束端口占用检查的条件判断

    # 配置规则备注
    echo ""
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"

    # 检查是否有现有备注（端口复用情况）
    if [ -n "$RULE_NOTE" ]; then
        read -p "请输入新的备注(回车使用现有备注$RULE_NOTE): " new_note
        new_note=$(echo "$new_note" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
        if [ -n "$new_note" ]; then
            RULE_NOTE="$new_note"
            echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
        else
            echo -e "${GREEN}使用现有备注: $RULE_NOTE${NC}"
        fi
    else
        read -p "请输入当前规则备注(可选，直接回车跳过): " RULE_NOTE
        # 去除前后空格并限制长度
        RULE_NOTE=$(echo "$RULE_NOTE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
        if [ -n "$RULE_NOTE" ]; then
            echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
        else
            echo -e "${BLUE}未设置备注${NC}"
        fi
    fi

    echo ""
}

# 出口服务器交互配置
configure_exit_server() {
    echo -e "${YELLOW}=== 落地服务器配置 (双端Realm架构) ===${NC}"
    echo ""

    # 显示本机公网IP
    echo "正在获取本机公网IP..."
    local ipv4=$(get_public_ip "ipv4")
    local ipv6=$(get_public_ip "ipv6")

    if [ -n "$ipv4" ]; then
        echo -e "${GREEN}本机IPv4地址: $ipv4${NC}"
    fi
    if [ -n "$ipv6" ]; then
        echo -e "${GREEN}本机IPv6地址: $ipv6${NC}"
    fi

    if [ -z "$ipv4" ] && [ -z "$ipv6" ]; then
        echo -e "${YELLOW}无法自动获取公网IP，请手动确认${NC}"
    fi
    echo ""

    # 配置监听端口
    while true; do
        read -p "请输入监听端口 (等待中转服务器连接的端口，NAT VPS需使用商家分配的端口): " EXIT_LISTEN_PORT
        if validate_port "$EXIT_LISTEN_PORT"; then
            echo -e "${GREEN}监听端口设置为: $EXIT_LISTEN_PORT${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字${NC}"
        fi
    done

    # 诊断端口占用
    check_port_usage "$EXIT_LISTEN_PORT" "出口服务器监听"

    echo ""

    # 配置转发目标
    echo "配置转发目标 (就是设置好的本地业务软件,服务等等的信息):"
    echo ""
    echo -e "${YELLOW}双端Realm架构${NC}"
    echo -e "${YELLOW}ipv4输入127.0.0.1,IPv6输入: ::1${NC}"
    echo ""

    # 转发目标地址配置（简化）
    while true; do
        read -p "转发目标IP地址(默认:127.0.0.1): " input_target
        if [ -z "$input_target" ]; then
            input_target="127.0.0.1"
        fi

        if validate_target_address "$input_target"; then
            FORWARD_TARGET="$input_target"
            echo -e "${GREEN}转发目标设置为: $FORWARD_TARGET${NC}"

            # 如果是多地址，给出提示
            if [[ "$FORWARD_TARGET" == *","* ]]; then
                echo -e "${BLUE}提示: 检测到多个地址，将支持IPv4/IPv6双栈转发${NC}"
            fi
            break
        else
            echo -e "${RED}无效地址格式${NC}"
            echo -e "${YELLOW}支持格式: IP地址、域名、或多个地址用逗号分隔${NC}"
            echo -e "${YELLOW}示例: 127.0.0.1,::1 或 localhost 或 192.168.1.100${NC}"
        fi
    done

    # 转发目标端口配置
    local forward_port
    while true; do
        read -p "转发目标端口(业务端口): " forward_port
        if validate_port "$forward_port"; then
            echo -e "${GREEN}转发端口设置为: $forward_port${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字${NC}"
        fi
    done

    # 组合完整的转发目标（包含端口）
    FORWARD_TARGET="$FORWARD_TARGET:$forward_port"

    # 测试转发目标连通性
    echo -e "${YELLOW}正在测试转发目标连通性...${NC}"
    local connectivity_ok=true

    # 解析并测试每个地址
    local addresses_part="${FORWARD_TARGET%:*}"
    local target_port="${FORWARD_TARGET##*:}"
    IFS=',' read -ra TARGET_ADDRESSES <<< "$addresses_part"
    for addr in "${TARGET_ADDRESSES[@]}"; do
        addr=$(echo "$addr" | xargs)  # 去除空格
        echo -e "${BLUE}测试连接: $addr:$target_port${NC}"
        if check_connectivity "$addr" "$target_port"; then
            echo -e "${GREEN}✓ $addr:$target_port 连接成功${NC}"
        else
            echo -e "${RED}✗ $addr:$target_port 连接失败${NC}"
            connectivity_ok=false
        fi
    done

    if ! $connectivity_ok; then
        echo -e "${RED}部分或全部转发目标连接测试失败，请确认代理服务是否正常运行${NC}"

        # 检查是否包含域名，给出DDNS特别提醒
        local has_domain=false
        local addresses_part="${FORWARD_TARGET%:*}"
        IFS=',' read -ra TARGET_ADDRESSES <<< "$addresses_part"
        for addr in "${TARGET_ADDRESSES[@]}"; do
            addr=$(echo "$addr" | xargs)
            if ! validate_ip "$addr" && [[ "$addr" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                has_domain=true
                break
            fi
        done

        if $has_domain; then
            echo -e "${YELLOW}检测到您使用的是域名地址，如果是DDNS域名：${NC}"
            echo -e "${YELLOW}确认域名和端口正确，可以直接继续配置无需担心${NC}"
            echo -e "${YELLOW}DDNS域名无法进行连通性测试${NC}"
        fi

        read -p "是否继续配置？(y/n): " continue_config
        if [[ ! "$continue_config" =~ ^[Yy]$ ]]; then
            echo "配置已取消"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ 所有转发目标连接测试成功！${NC}"
    fi

    # 已移除FORWARD_IP兼容性变量，统一使用FORWARD_TARGET

    # 传输模式选择
    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} WebSocket (ws)"
    echo -e "${GREEN}[3]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[4]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (自签证书)"
    echo -e "${GREEN}[6]${NC} TLS+WebSocket (CA证书)"
    echo ""

    while true; do
        read -p "请输入选择 [1-6]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="ws"
                echo -e "${GREEN}已选择: WebSocket${NC}"

                # WebSocket路径配置
                echo ""
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            3)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            4)
                SECURITY_LEVEL="tls_ca"
                echo -e "${GREEN}已选择: TLS CA证书${NC}"

                # 证书路径配置
                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME
                echo -e "${GREEN}TLS配置完成${NC}"
                break
                ;;
            5)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME="$DEFAULT_SNI_DOMAIN"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"

                # WebSocket路径配置
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}WebSocket路径设置为: $WS_PATH${NC}"
                break
                ;;
            6)
                SECURITY_LEVEL="ws_tls_ca"
                echo -e "${GREEN}已选择: TLS+WebSocket CA证书${NC}"

                # 证书路径配置
                echo ""
                while true; do
                    read -p "请输入证书文件路径: " TLS_CERT_PATH
                    if [ -f "$TLS_CERT_PATH" ]; then
                        break
                    else
                        echo -e "${RED}证书文件不存在，请检查路径${NC}"
                    fi
                done

                while true; do
                    read -p "请输入私钥文件路径: " TLS_KEY_PATH
                    if [ -f "$TLS_KEY_PATH" ]; then
                        break
                    else
                        echo -e "${RED}私钥文件不存在，请检查路径${NC}"
                    fi
                done

                read -p "请输入TLS服务器名称 (SNI): " TLS_SERVER_NAME

                # WebSocket路径配置
                read -p "请输入WebSocket路径 [默认: /ws]: " WS_PATH
                if [ -z "$WS_PATH" ]; then
                    WS_PATH="/ws"
                fi
                echo -e "${GREEN}TLS+WebSocket配置完成${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                ;;
        esac
    done

    # 配置规则备注
    echo ""
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"

    read -p "请输入当前规则备注(可选，直接回车跳过): " RULE_NOTE
    # 去除前后空格并限制长度
    RULE_NOTE=$(echo "$RULE_NOTE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-50)
    if [ -n "$RULE_NOTE" ]; then
        echo -e "${GREEN}备注设置为: $RULE_NOTE${NC}"
    else
        echo -e "${BLUE}未设置备注${NC}"
    fi

    echo ""
}

# 检测虚拟化环境
detect_virtualization() {
    local virt_type="物理机"

    # 检测各种虚拟化技术
    if [ -f /proc/vz/version ]; then
        virt_type="OpenVZ"
    elif [ -d /proc/vz ]; then
        virt_type="OpenVZ容器"
    elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
        virt_type="LXC容器"
    elif [ -f /.dockerenv ]; then
        virt_type="Docker容器"
    elif command -v systemd-detect-virt >/dev/null 2>&1; then
        local detected=$(systemd-detect-virt 2>/dev/null)
        case "$detected" in
            "kvm") virt_type="KVM虚拟机" ;;
            "qemu") virt_type="QEMU虚拟机" ;;
            "vmware") virt_type="VMware虚拟机" ;;
            "xen") virt_type="Xen虚拟机" ;;
            "lxc") virt_type="LXC容器" ;;
            "docker") virt_type="Docker容器" ;;
            "openvz") virt_type="OpenVZ容器" ;;
            "none") virt_type="物理机" ;;
            *) virt_type="未知虚拟化($detected)" ;;
        esac
    elif [ -e /proc/user_beancounters ]; then
        virt_type="OpenVZ容器"
    elif dmesg 2>/dev/null | grep -i "hypervisor detected" >/dev/null; then
        virt_type="虚拟机"
    fi

    echo "$virt_type"
}

# 获取适合的临时目录（针对不同虚拟化环境）
get_temp_dir() {
    local virt_env=$(detect_virtualization)
    local temp_candidates=()

    # 根据虚拟化环境选择最佳临时目录
    case "$virt_env" in
        *"LXC"*|*"OpenVZ"*)
            # 容器环境优先使用 /var/tmp，避免权限问题
            temp_candidates=("/var/tmp" "/tmp" ".")
            ;;
        *"Docker"*)
            # Docker 环境优先使用当前目录
            temp_candidates=("." "/tmp" "/var/tmp")
            ;;
        *)
            # 其他环境使用标准顺序
            temp_candidates=("/tmp" "/var/tmp" ".")
            ;;
    esac

    # 测试每个候选目录
    for dir in "${temp_candidates[@]}"; do
        if [ -w "$dir" ]; then
            local test_file="${dir}/test_write_$$"
            if echo "test" > "$test_file" 2>/dev/null; then
                rm -f "$test_file"
                echo "$dir"
                return 0
            fi
        fi
    done

    # 如果都不可用，返回当前目录
    echo "."
}

# 系统诊断函数 - 虚拟化适配
diagnose_system() {
    echo -e "${YELLOW}=== 系统诊断信息 ===${NC}"

    # 检测虚拟化环境
    local virt_env=$(detect_virtualization)
    echo -e "${BLUE}虚拟化环境: ${GREEN}${virt_env}${NC}"

    # 检查磁盘空间
    echo -e "${BLUE}磁盘空间:${NC}"
    df -h . 2>/dev/null | head -2 || echo "无法获取磁盘信息"

    # 检查内存使用
    echo -e "${BLUE}内存使用:${NC}"
    free -h 2>/dev/null | head -2 || echo "无法获取内存信息"

    # 检查文件系统类型
    echo -e "${BLUE}文件系统类型:${NC}"
    local fs_type=$(df -T . 2>/dev/null | tail -1 | awk '{print $2}' || echo "未知")
    echo "当前目录文件系统: $fs_type"

    # 针对不同虚拟化环境的特殊检查
    case "$virt_env" in
        *"LXC"*|*"OpenVZ"*)
            echo -e "${BLUE}容器特殊检查:${NC}"
            echo "容器ID: $(cat /proc/self/cgroup 2>/dev/null | head -1 | cut -d: -f3 || echo '未知')"
            echo "用户命名空间: $(readlink /proc/self/ns/user 2>/dev/null || echo '未知')"
            # LXC/OpenVZ 特有的权限检查
            if [ -e /proc/user_beancounters ]; then
                echo "OpenVZ beancounters: 存在"
            fi
            ;;
        *"Docker"*)
            echo -e "${BLUE}Docker特殊检查:${NC}"
            echo "容器ID: $(hostname 2>/dev/null || echo '未知')"
            ;;
    esac

    # 测试文件写入（多个位置）
    echo -e "${BLUE}文件写入测试:${NC}"
    local write_locations=("." "/tmp" "/var/tmp")

    for location in "${write_locations[@]}"; do
        if [ -w "$location" ]; then
            local test_file="${location}/test_write_$$"
            if echo "test" > "$test_file" 2>/dev/null; then
                echo -e "${GREEN}✓ ${location} 可写${NC}"
                rm -f "$test_file"
            else
                echo -e "${RED}✗ ${location} 写入失败${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ ${location} 无写入权限${NC}"
        fi
    done

    # 推荐的临时目录
    local recommended_temp=$(get_temp_dir)
    echo -e "${BLUE}推荐临时目录: ${GREEN}${recommended_temp}${NC}"

    echo ""
}

# 多线程并行搜索xwPF.sh脚本位置（带缓存）
find_script_locations_enhanced() {
    local cache_file="/tmp/xwPF_script_locations_cache"
    local cache_timeout=604800  # 7天缓存，用户几乎不会改变脚本位置

    # 检查缓存是否有效
    if [ -f "$cache_file" ]; then
        local cache_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ $cache_age -lt $cache_timeout ]; then
            cat "$cache_file"
            return 0
        fi
    fi

    echo -e "${BLUE}正在多线程搜索脚本位置...${NC}" >&2

    local temp_file=$(mktemp)
    local search_roots=("/" "/usr" "/opt" "/home" "/root" "/var" "/tmp" "/etc")

    # 并行搜索不同的根目录
    for root in "${search_roots[@]}"; do
        if [ -d "$root" ] && [ -r "$root" ]; then
            (
                # 使用timeout避免搜索卡死
                if command -v timeout >/dev/null 2>&1; then
                    timeout 30 find "$root" -name "xwPF.sh" -type f 2>/dev/null | while read -r file; do
                        if [ -f "$file" ] && [ -r "$file" ]; then
                            echo "$(dirname "$file")" >> "$temp_file"
                        fi
                    done
                else
                    find "$root" -name "xwPF.sh" -type f 2>/dev/null | while read -r file; do
                        if [ -f "$file" ] && [ -r "$file" ]; then
                            echo "$(dirname "$file")" >> "$temp_file"
                        fi
                    done
                fi
            ) &
        fi
    done
    wait  # 等待所有搜索完成

    # 处理搜索结果
    local all_locations=()
    if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
        while IFS= read -r dir; do
            if [ -d "$dir" ] && [ -r "$dir" ]; then
                all_locations+=("$dir")
            fi
        done < <(sort -u "$temp_file")
    fi
    rm -f "$temp_file"

    # 评分和排序
    local scored_locations=()
    for dir in "${all_locations[@]}"; do
        local score=0
        local path_length=${#dir}

        # 用户自定义位置优先（非系统目录）+20分
        if [[ "$dir" != "/usr/local/bin" && "$dir" != "/usr/bin" && "$dir" != "/bin" && "$dir" != "/usr/sbin" ]]; then
            score=$((score + 20))
        fi

        # 包含realm压缩包+15分
        if ls "$dir"/realm-*.tar.gz >/dev/null 2>&1 || ls "$dir"/realm-*.zip >/dev/null 2>&1; then
            score=$((score + 15))
        fi

        # 包含JSON配置文件+10分
        if ls "$dir"/*.json >/dev/null 2>&1; then
            score=$((score + 10))
        fi

        # 包含其他配置文件+5分
        if ls "$dir"/*.conf >/dev/null 2>&1 || ls "$dir"/*.yaml >/dev/null 2>&1; then
            score=$((score + 5))
        fi

        # 当前工作目录+3分
        if [ "$dir" = "$(pwd)" ]; then
            score=$((score + 3))
        fi

        # 路径越短越好（用于同分情况下的排序）
        scored_locations+=("$score:$path_length:$dir")
    done

    # 按分数排序（分数高的在前），分数相同时按路径长度排序（短的在前）
    local sorted_locations=($(printf '%s\n' "${scored_locations[@]}" | sort -t: -k1,1nr -k2,2n))

    # 提取目录路径并保存到缓存
    local final_locations=()
    for item in "${sorted_locations[@]}"; do
        local dir=$(echo "$item" | cut -d: -f3)
        final_locations+=("$dir")
    done

    # 保存到缓存
    printf '%s\n' "${final_locations[@]}" > "$cache_file"

    # 输出结果
    printf '%s\n' "${final_locations[@]}"
}





# 确定工作目录 - 统一逻辑
get_work_dir() {
    local virt_env=$(detect_virtualization)

    # 只有这些容器环境需要特殊处理
    case "$virt_env" in
        *"LXC"*|*"OpenVZ"*|*"Docker"*)
            local temp_dir=$(get_temp_dir)
            echo "$temp_dir"
            ;;
        *)
            # 所有其他环境（KVM、VMware、物理机等）都用当前目录
            echo "."
            ;;
    esac
}

# 从本地压缩包安装realm
install_realm_from_local_package() {
    local package_path="$1"
    local temp_dir=$(mktemp -d)

    echo -e "${YELLOW}正在从本地压缩包安装 realm...${NC}"
    echo -e "${BLUE}压缩包: $(basename "$package_path")${NC}"

    # 解压到临时目录
    if [[ "$package_path" == *.tar.gz ]]; then
        if ! tar -xzf "$package_path" -C "$temp_dir" 2>/dev/null; then
            echo -e "${RED}✗ 解压失败${NC}"
            rm -rf "$temp_dir"
            return 1
        fi
    elif [[ "$package_path" == *.zip ]]; then
        if ! unzip -q "$package_path" -d "$temp_dir" 2>/dev/null; then
            echo -e "${RED}✗ 解压失败${NC}"
            rm -rf "$temp_dir"
            return 1
        fi
    else
        echo -e "${RED}✗ 不支持的压缩包格式${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    # 查找realm二进制文件
    local realm_binary=$(find "$temp_dir" -name "realm" -type f -executable 2>/dev/null | head -1)

    if [ -n "$realm_binary" ] && [ -f "$realm_binary" ]; then
        # 检查并停止正在运行的realm服务
        local service_was_running=$(safe_stop_realm_service)
        if [ $? -ne 0 ]; then
            rm -rf "$temp_dir"
            return 1
        fi

        # 复制到目标位置
        if cp "$realm_binary" "$REALM_PATH" && chmod +x "$REALM_PATH"; then
            echo -e "${GREEN}✓ realm 安装成功${NC}"

            # 根据之前的服务状态决定重启方式（更新场景）
            restart_realm_service "$service_was_running" true

            rm -rf "$temp_dir"
            return 0
        else
            echo -e "${RED}✗ 复制文件失败${NC}"
            rm -rf "$temp_dir"
            return 1
        fi
    else
        echo -e "${RED}✗ 压缩包中未找到 realm 二进制文件${NC}"
        rm -rf "$temp_dir"
        return 1
    fi
}

# 统一多源下载函数
download_from_sources() {
    local url="$1"
    local target_path="$2"

    for proxy in "${DOWNLOAD_SOURCES[@]}"; do
        local full_url="${proxy}${url}"
        local source_name

        if [ -z "$proxy" ]; then
            source_name="GitHub官方源"
        else
            source_name="加速源: $(echo "$proxy" | sed 's|https://||' | sed 's|/$||')"
        fi

        # 将状态消息重定向到 stderr (>&2)
        echo -e "${BLUE}尝试 $source_name${NC}" >&2

        if curl -fsSL --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT "$full_url" -o "$target_path"; then
            echo -e "${GREEN}✓ $source_name 下载成功${NC}" >&2
            return 0
        else

            echo -e "${YELLOW}✗ $source_name 下载失败，尝试下一个源...${NC}" >&2
        fi
    done

    echo -e "${RED}✗ 所有下载源均失败${NC}" >&2
    return 1
}

# 多源下载策略（保持向后兼容）
download_with_fallback() {
    local base_url="$1"
    local filename="$2"

    # 确定工作目录
    local work_dir=$(get_work_dir)
    if [ "$work_dir" = "." ]; then
        work_dir="$(pwd)"
    fi

    local file_path="${work_dir}/${filename}"

    # 使用统一的多源下载函数
    if download_from_sources "$base_url" "$file_path"; then
        echo "$file_path"  # 返回文件路径
        return 0
    else
        return 1
    fi
}

# 简洁高效的下载函数
reliable_download() {
    local url="$1"
    local filename="$2"

    # 确定工作目录
    local work_dir=$(get_work_dir)
    if [ "$work_dir" = "." ]; then
        work_dir="$(pwd)"
    fi

    local file_path="${work_dir}/${filename}"
    rm -f "$file_path"

    # curl下载（带进度条）
    if command -v curl >/dev/null 2>&1; then
        if curl -L --progress-bar --fail --connect-timeout $LONG_CONNECT_TIMEOUT --max-time $LONG_MAX_TIMEOUT -o "$file_path" "$url"; then
            if [ -f "$file_path" ] && [ -s "$file_path" ]; then
                echo "$file_path"
                return 0
            fi
        fi
    fi

    # wget备用
    if command -v wget >/dev/null 2>&1; then
        rm -f "$file_path"
        if wget --progress=bar:force -O "$file_path" "$url"; then
            if [ -f "$file_path" ] && [ -s "$file_path" ]; then
                echo "$file_path"
                return 0
            fi
        fi
    fi

    rm -f "$file_path"
    return 1
}

# 获取realm最新版本号
get_latest_realm_version() {
    echo -e "${YELLOW}获取最新版本信息...${NC}" >&2

    # 直接解析releases页面获取版本号，超时机制
    local latest_version=$(curl -sL --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT "https://github.com/zhboner/realm/releases" 2>/dev/null | \
        head -2100 | \
        sed -n 's|.*releases/tag/v\([0-9.]*\).*|v\1|p' | head -1)

    # 如果失败，使用硬编码版本号
    if [ -z "$latest_version" ]; then
        echo -e "${YELLOW}使用当前最新版本 v2.9.1${NC}" >&2
        latest_version="v2.9.2"
    fi

    echo -e "${GREEN}✓ 检测到最新版本: ${latest_version}${NC}" >&2
    echo "$latest_version"
}

# 智能重启realm服务
restart_realm_service() {
    local was_running="$1"
    local is_update="${2:-false}"  # 是否为更新场景

    if [ "$was_running" = true ] || [ "$is_update" = true ]; then
        echo -e "${YELLOW}正在启动realm服务...${NC}"
        if systemctl start realm >/dev/null 2>&1; then
            echo -e "${GREEN}✓ realm服务已启动${NC}"
        else
            echo -e "${YELLOW}服务启动失败，尝试重新初始化...${NC}"
            start_empty_service
        fi
    else
        # 首次安装，启动空服务完成安装
        start_empty_service
    fi
}

# 比较realm版本并询问更新
compare_and_ask_update() {
    local current_version="$1"
    local latest_version="$2"

    # 提取当前版本号进行比较
    local current_ver=$(echo "$current_version" | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -z "$current_ver" ]; then
        current_ver="v0.0.0"  # 如果无法提取版本号，假设为旧版本
    fi

    # 统一版本格式（都添加v前缀）
    if [[ ! "$current_ver" =~ ^v ]]; then
        current_ver="v$current_ver"
    fi
    if [[ ! "$latest_version" =~ ^v ]]; then
        latest_version="v$latest_version"
    fi

    # 比较版本
    if [ "$current_ver" = "$latest_version" ]; then
        echo -e "${GREEN}✓ 当前版本已是最新版本${NC}"
        return 1
    else
        echo -e "${YELLOW}发现新版本: ${current_ver} → ${latest_version}${NC}"
        read -p "是否更新到最新版本？(y/n) [默认: n]: " update_choice
        if [[ ! "$update_choice" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}使用现有的 realm 安装${NC}"
            return 1
        fi
        echo -e "${YELLOW}将更新到最新版本...${NC}"
        return 0
    fi
}

# 安全停止realm服务
safe_stop_realm_service() {
    local service_was_running=false

    if systemctl is-active realm >/dev/null 2>&1; then
        echo -e "${BLUE}检测到realm服务正在运行，正在停止服务...${NC}"
        if systemctl stop realm >/dev/null 2>&1; then
            echo -e "${GREEN}✓ realm服务已停止${NC}"
            service_was_running=true
        else
            echo -e "${RED}✗ 停止realm服务失败，无法安全更新${NC}"
            return 1
        fi
    fi

    echo "$service_was_running"
}

# 安装 realm - 虚拟化适配
install_realm() {
    echo -e "${GREEN}正在检查 realm 安装状态...${NC}"

    # 检测虚拟化环境并显示
    local virt_env=$(detect_virtualization)
    echo -e "${BLUE}检测到虚拟化环境: ${GREEN}${virt_env}${NC}"

    # 检查是否已安装realm
    if [ -f "${REALM_PATH}" ] && [ -x "${REALM_PATH}" ]; then
        # 检查程序完整性（基本可执行性测试）
        if ! ${REALM_PATH} --help >/dev/null 2>&1; then
            echo -e "${YELLOW}检测到 realm 文件存在但可能已损坏，将重新安装...${NC}"
        else
            # 尝试获取版本信息
            local current_version=""
            local version_output=""
            if version_output=$(${REALM_PATH} --version 2>&1); then
                current_version="$version_output"
            elif version_output=$(${REALM_PATH} -v 2>&1); then
                current_version="$version_output"
            else
                current_version="realm (版本检查失败，可能架构不匹配)"
                echo -e "${YELLOW}警告: 版本检查失败，错误信息: ${version_output}${NC}"
            fi

            echo -e "${GREEN}✓ 检测到已安装的 realm: ${current_version}${NC}"
            echo ""

            # 获取最新版本号进行比较
            LATEST_VERSION=$(get_latest_realm_version)

            # 比较版本并询问更新
            if ! compare_and_ask_update "$current_version" "$LATEST_VERSION"; then
                return 0
            fi
        fi
    else
        echo -e "${YELLOW}未检测到 realm 安装，开始下载安装...${NC}"

        # 获取最新版本号
        LATEST_VERSION=$(get_latest_realm_version)
    fi

    # 检测本地压缩包
    echo -e "${YELLOW}检测本地 realm 压缩包...${NC}"
    local locations=($(find_script_locations_enhanced))
    local script_dir="${locations[0]}"
    echo -e "${BLUE}脚本工作目录: $script_dir${NC}"

    local local_packages=($(find "$script_dir" -maxdepth 1 -name "realm-*.tar.gz" -o -name "realm-*.zip" 2>/dev/null))

    if [ ${#local_packages[@]} -gt 0 ]; then
        echo -e "${GREEN}✓ 发现本地 realm 压缩包: $(basename "${local_packages[0]}")${NC}"
        read -p "是否使用本地压缩包安装？(y/n) [默认: y]: " use_local
        if [[ "$use_local" =~ ^[Nn]$ ]]; then
            echo -e "${BLUE}跳过本地安装，使用在线下载...${NC}"
        else
            if install_realm_from_local_package "${local_packages[0]}"; then
                echo -e "${GREEN}✓ 本地压缩包安装成功${NC}"
                # 启动空服务完成安装
                start_empty_service
                return 0
            else
                echo -e "${YELLOW}本地安装失败，继续在线下载...${NC}"
            fi
        fi
    else
        echo -e "${BLUE}未发现本地压缩包，使用在线下载...${NC}"
    fi

    # 检测系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="x86_64-unknown-linux-gnu"
            ;;
        aarch64)
            ARCH="aarch64-unknown-linux-gnu"
            ;;
        armv7l|armv6l|arm)
            ARCH="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            echo -e "${RED}不支持的CPU架构: ${ARCH}${NC}"
            echo -e "${YELLOW}支持的架构: x86_64, aarch64, armv7l${NC}"
            exit 1
            ;;
    esac

    # 构建下载URL - 支持多源下载
    DOWNLOAD_URL="https://github.com/zhboner/realm/releases/download/${LATEST_VERSION}/realm-${ARCH}.tar.gz"
    echo -e "${BLUE}目标文件: realm-${ARCH}.tar.gz${NC}"

    # 使用多源下载策略
    local download_file=""
    if download_file=$(download_with_fallback "$DOWNLOAD_URL" "realm.tar.gz"); then
        echo -e "${GREEN}✓ 下载成功: ${download_file}${NC}"
    else
        echo -e "${RED}✗ 下载失败${NC}"
        exit 1
    fi

    # 解压安装
    echo -e "${YELLOW}正在解压安装...${NC}"

    # 检查并停止正在运行的realm服务
    local service_was_running=$(safe_stop_realm_service)
    if [ $? -ne 0 ]; then
        return 1
    fi

    # 解压安装
    local work_dir=$(dirname "$download_file")
    local archive_name=$(basename "$download_file")

    if (cd "$work_dir" && tar -xzf "$archive_name" && cp realm ${REALM_PATH} && chmod +x ${REALM_PATH}); then
        echo -e "${GREEN}✓ realm 安装成功${NC}"
        rm -f "$download_file" "${work_dir}/realm"

        # 根据之前的服务状态决定重启方式（更新场景）
        restart_realm_service "$service_was_running" true
    else
        echo -e "${RED}✗ 安装失败${NC}"
        exit 1
    fi
}

# 生成单个规则的endpoint配置（支持多地址和负载均衡）
generate_rule_endpoint_config() {
    local remote_host="$1"
    local remote_port="$2"
    local listen_port="$3"
    local security_level="$4"
    local tls_server_name="$5"
    local tls_cert_path="$6"
    local tls_key_path="$7"
    local balance_mode="$8"
    local target_states="$9"

    local endpoint_config=""

    # 检查是否为多地址
    if [[ "$remote_host" == *","* ]]; then
        # 多地址配置：使用主地址+额外地址
        IFS=',' read -ra addresses <<< "$remote_host"
        local main_address="${addresses[0]}"
        local extra_addresses=""
        local enabled_addresses=()

        # 根据TARGET_STATES过滤启用的地址
        enabled_addresses+=("$main_address")  # 主地址默认启用

        if [ ${#addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#addresses[@]}; i++)); do
                local is_enabled=$(is_target_enabled "$i" "$target_states")

                if [ "$is_enabled" = "true" ]; then
                    enabled_addresses+=("${addresses[i]}")
                fi
            done
        fi

        # 构建额外地址字符串（只包含启用的地址）
        if [ ${#enabled_addresses[@]} -gt 1 ]; then
            for ((i=1; i<${#enabled_addresses[@]}; i++)); do
                if [ -n "$extra_addresses" ]; then
                    extra_addresses="$extra_addresses, "
                fi
                extra_addresses="$extra_addresses\"${enabled_addresses[i]}:${remote_port}\""
            done

            extra_addresses=",
            \"extra_remotes\": [$extra_addresses]"
        fi

        endpoint_config="
        {
            \"listen\": \"${LISTEN_IP:-${NAT_LISTEN_IP:-::}}:${listen_port}\",
            \"remote\": \"${enabled_addresses[0]}:${remote_port}\"${extra_addresses}"
    else
        # 单地址配置
        endpoint_config="
        {
            \"listen\": \"${LISTEN_IP:-${NAT_LISTEN_IP:-::}}:${listen_port}\",
            \"remote\": \"${remote_host}:${remote_port}\""
    fi

    # 添加through字段（仅中转服务器）
    local role="${RULE_ROLE:-1}"
    if [ "$role" = "1" ] && [ -n "$THROUGH_IP" ] && [ "$THROUGH_IP" != "::" ]; then
        endpoint_config="$endpoint_config,
            \"through\": \"$THROUGH_IP\""
    fi

    # 添加负载均衡配置（仅用于单规则多地址情况）
    if [ -n "$balance_mode" ] && [ "$balance_mode" != "off" ] && [[ "$remote_host" == *","* ]]; then
        # 计算地址数量并生成权重
        IFS=',' read -ra addr_array <<< "$remote_host"
        local weights=""
        for ((i=0; i<${#addr_array[@]}; i++)); do
            if [ -n "$weights" ]; then
                weights="$weights, "
            fi
            weights="${weights}1"  # 默认权重为1（相等权重）
        done

        endpoint_config="$endpoint_config,
            \"balance\": \"$balance_mode: $weights\""
    fi

    # 添加传输配置 - 需要角色信息
    # 通过全局变量RULE_ROLE获取角色，如果没有则通过REMOTE_HOST判断
    local role="${RULE_ROLE:-1}"  # 默认为中转服务器
    if [ -z "$RULE_ROLE" ]; then
        # 如果没有RULE_ROLE，通过是否有FORWARD_TARGET判断
        if [ -n "$FORWARD_TARGET" ]; then
            role="2"  # 出口服务器
        fi
    fi

    local transport_config=$(get_transport_config "$security_level" "$tls_server_name" "$tls_cert_path" "$tls_key_path" "$role" "$WS_PATH")
    if [ -n "$transport_config" ]; then
        endpoint_config="$endpoint_config,
            $transport_config"
    fi

    endpoint_config="$endpoint_config
        }"

    echo "$endpoint_config"
}

# 100%成功率的文件查找
find_file_path() {
    local filename="$1"
    local cache_file="/tmp/realm_path_cache"

    # 检查缓存
    if [ -f "$cache_file" ]; then
        local cached_path=$(grep "^$filename:" "$cache_file" 2>/dev/null | cut -d: -f2)
        if [ -n "$cached_path" ] && [ -f "$cached_path" ]; then
            echo "$cached_path"
            return 0
        fi
    fi

    # 第一阶段：常见位置直接检查
    local common_paths=(
        "/etc/realm/health/$filename"
        "/etc/realm/$filename"
        "/var/lib/realm/$filename"
        "/opt/realm/$filename"
        "/usr/local/etc/realm/$filename"
        "/var/cache/realm/$filename"
        "/tmp/realm/$filename"
        "/home/*/realm/$filename"
        "/root/realm/$filename"
    )

    for path in "${common_paths[@]}"; do
        # 处理通配符路径
        if [[ "$path" == *"*"* ]]; then
            for expanded_path in $path; do
                if [ -f "$expanded_path" ]; then
                    echo "$filename:$expanded_path" >> "$cache_file"
                    echo "$expanded_path"
                    return 0
                fi
            done
        else
            if [ -f "$path" ]; then
                echo "$filename:$path" >> "$cache_file"
                echo "$path"
                return 0
            fi
        fi
    done

    # 第二阶段：分区域搜索（限制深度）
    local search_dirs=("/etc" "/var" "/opt" "/usr" "/home" "/root")
    for dir in "${search_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local found_path=""
            if command -v timeout >/dev/null 2>&1; then
                found_path=$(timeout 3 find "$dir" -maxdepth 4 -name "$filename" -type f 2>/dev/null | head -1)
            else
                found_path=$(find "$dir" -maxdepth 4 -name "$filename" -type f 2>/dev/null | head -1)
            fi

            if [ -n "$found_path" ] && [ -f "$found_path" ]; then
                echo "$filename:$found_path" >> "$cache_file"
                echo "$found_path"
                return 0
            fi
        fi
    done

    # 第三阶段：全系统搜索
    local found_path=""
    if command -v timeout >/dev/null 2>&1; then
        found_path=$(timeout 10 find / -name "$filename" -type f 2>/dev/null | head -1)
    else
        # 如果没有timeout，限制搜索范围避免卡死
        found_path=$(find /etc /var /opt /usr /home /root /tmp -name "$filename" -type f 2>/dev/null | head -1)
    fi

    if [ -n "$found_path" ] && [ -f "$found_path" ]; then
        echo "$filename:$found_path" >> "$cache_file"
        echo "$found_path"
        return 0
    fi

    return 1
}

# 从规则生成endpoints配置（支持负载均衡合并和故障转移）
generate_endpoints_from_rules() {
    local endpoints=""
    local count=0

    if [ ! -d "$RULES_DIR" ]; then
        return 0
    fi

    # 动态查找健康状态文件
    local health_status_file=$(find_file_path "health_status.conf")
    declare -A health_status

    # 读取健康状态文件（使用绝对路径）
    if [ -f "$health_status_file" ]; then
        while read -r line; do
            # 跳过注释行和空行
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue

            # 解析格式: RULE_ID|TARGET|STATUS|FAIL_COUNT|SUCCESS_COUNT|LAST_CHECK
            if [[ "$line" =~ ^[0-9]+\|([^|]+)\|([^|]+)\| ]]; then
                local host="${BASH_REMATCH[1]}"
                local status="${BASH_REMATCH[2]}"

                # 如果主机已经有状态记录，且当前状态是故障，则保持故障状态
                if [ "${health_status[$host]}" = "failed" ] || [ "$status" = "failed" ]; then
                    health_status["$host"]="failed"
                else
                    health_status["$host"]="$status"
                fi
            fi
        done < "$health_status_file"
    fi

    # 按监听端口分组规则
    declare -A port_groups
    declare -A port_configs
    declare -A port_weights
    declare -A port_roles

    # 第一步：收集所有启用的规则并按端口分组（不进行故障转移过滤）
    declare -A port_rule_files
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                local port_key="$LISTEN_PORT"

                # 存储端口配置（使用第一个规则的配置作为基准）
                if [ -z "${port_configs[$port_key]}" ]; then
                    # 根据角色决定默认监听IP
                    local default_listen_ip
                    if [ "$RULE_ROLE" = "2" ]; then
                        # 落地服务器使用双栈监听
                        default_listen_ip="::"
                    else
                        # 中转服务器使用动态输入的IP
                        default_listen_ip="${NAT_LISTEN_IP:-::}"
                    fi
                    port_configs[$port_key]="$SECURITY_LEVEL|$TLS_SERVER_NAME|$TLS_CERT_PATH|$TLS_KEY_PATH|$BALANCE_MODE|${LISTEN_IP:-$default_listen_ip}|$THROUGH_IP"
                    # 存储权重配置和角色信息
                    port_weights[$port_key]="$WEIGHTS"
                    port_roles[$port_key]="$RULE_ROLE"
                elif [ "${port_roles[$port_key]}" != "$RULE_ROLE" ]; then
                    # 检测到同一端口有不同角色的规则，跳过此规则
                    echo -e "${YELLOW}警告: 端口 $port_key 已被角色 ${port_roles[$port_key]} 的规则占用，跳过角色 $RULE_ROLE 的规则${NC}" >&2
                    continue
                fi

                # 收集目标：根据规则角色使用不同的字段
                local targets_to_add=""

                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    targets_to_add="$FORWARD_TARGET"
                else
                    # 中转服务器：优先使用TARGET_STATES，否则使用REMOTE_HOST
                    if [ "$BALANCE_MODE" != "off" ] && [ -n "$TARGET_STATES" ]; then
                        # 负载均衡模式且有TARGET_STATES，使用TARGET_STATES
                        targets_to_add="$TARGET_STATES"
                    else
                        # 非负载均衡模式或无TARGET_STATES，使用REMOTE_HOST:REMOTE_PORT
                        if [[ "$REMOTE_HOST" == *","* ]]; then
                            # REMOTE_HOST包含多个地址
                            IFS=',' read -ra host_list <<< "$REMOTE_HOST"
                            for host in "${host_list[@]}"; do
                                host=$(echo "$host" | xargs)  # 去除空格
                                if [ -n "$targets_to_add" ]; then
                                    targets_to_add="$targets_to_add,$host:$REMOTE_PORT"
                                else
                                    targets_to_add="$host:$REMOTE_PORT"
                                fi
                            done
                        else
                            # REMOTE_HOST是单个地址
                            targets_to_add="$REMOTE_HOST:$REMOTE_PORT"
                        fi
                    fi
                fi

                # 将目标添加到端口组（避免重复）
                if [ -n "$targets_to_add" ]; then
                    IFS=',' read -ra target_list <<< "$targets_to_add"
                    for target in "${target_list[@]}"; do
                        target=$(echo "$target" | xargs)  # 去除空格
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    done
                fi

                # 记录规则文件以便后续检查故障转移状态
                if [ -z "${port_rule_files[$port_key]}" ]; then
                    port_rule_files[$port_key]="$rule_file"
                fi
            fi
        fi
    done

    # 第二步：对每个端口组应用故障转移过滤
    for port_key in "${!port_groups[@]}"; do
        # 检查该端口的所有规则，只要有一个启用故障转移就应用过滤
        local failover_enabled="false"

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ] && read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$LISTEN_PORT" = "$port_key" ]; then
                if [ "${FAILOVER_ENABLED:-false}" = "true" ]; then
                    failover_enabled="true"
                    break
                fi
            fi
        done

        if [ "$failover_enabled" = "true" ]; then
            # 应用故障转移过滤
            IFS=',' read -ra all_targets <<< "${port_groups[$port_key]}"
            local filtered_targets=""
            local filtered_indices=()

            # 记录健康节点的索引位置
            for i in "${!all_targets[@]}"; do
                local target="${all_targets[i]}"
                local host="${target%:*}"
                local node_status="${health_status[$host]:-healthy}"

                if [ "$node_status" != "failed" ]; then
                    if [ -n "$filtered_targets" ]; then
                        filtered_targets="$filtered_targets,$target"
                    else
                        filtered_targets="$target"
                    fi
                    filtered_indices+=($i)
                fi
            done

            # 如果所有节点都故障，保留第一个节点避免服务完全中断
            if [ -z "$filtered_targets" ]; then
                filtered_targets="${all_targets[0]}"
                filtered_indices=(0)
            fi

            # 更新端口组为过滤后的目标
            port_groups[$port_key]="$filtered_targets"

            # 同步调整权重配置以匹配过滤后的目标数量
            local original_weights="${port_weights[$port_key]}"

            if [ -n "$original_weights" ]; then
                IFS=',' read -ra weight_array <<< "$original_weights"
                local adjusted_weights=""

                # 只保留健康节点对应的权重
                for index in "${filtered_indices[@]}"; do
                    if [ $index -lt ${#weight_array[@]} ]; then
                        local weight="${weight_array[index]}"
                        # 清理权重值（去除空格）
                        weight=$(echo "$weight" | tr -d ' ')
                        if [ -n "$adjusted_weights" ]; then
                            adjusted_weights="$adjusted_weights,$weight"
                        else
                            adjusted_weights="$weight"
                        fi
                    else
                        # 如果权重数组长度不足，使用默认权重1
                        if [ -n "$adjusted_weights" ]; then
                            adjusted_weights="$adjusted_weights,1"
                        else
                            adjusted_weights="1"
                        fi
                    fi
                done

                # 更新权重配置
                port_weights[$port_key]="$adjusted_weights"
            fi
        fi
    done

    # 为每个端口组生成endpoint配置
    for port_key in "${!port_groups[@]}"; do
        if [ $count -gt 0 ]; then
            endpoints="$endpoints,"
        fi

        # 解析端口配置
        IFS='|' read -r security_level tls_server_name tls_cert_path tls_key_path balance_mode listen_ip through_ip <<< "${port_configs[$port_key]}"
        # 如果没有listen_ip字段（向后兼容），根据角色使用对应的默认值
        if [ -z "$listen_ip" ]; then
            local role="${port_roles[$port_key]:-1}"
            if [ "$role" = "2" ]; then
                # 落地服务器使用双栈监听
                listen_ip="::"
            else
                # 中转服务器使用动态输入的IP
                listen_ip="${NAT_LISTEN_IP:-::}"
            fi
        fi

        # 如果没有through_ip字段（向后兼容），使用默认值
        if [ -z "$through_ip" ]; then
            through_ip="::"
        fi

        # 解析目标地址
        IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
        local main_target="${targets[0]}"
        local main_host="${main_target%:*}"
        local main_port="${main_target##*:}"

        # 构建extra_remotes
        local extra_remotes=""
        if [ ${#targets[@]} -gt 1 ]; then
            for ((i=1; i<${#targets[@]}; i++)); do
                if [ -n "$extra_remotes" ]; then
                    extra_remotes="$extra_remotes, "
                fi
                extra_remotes="$extra_remotes\"${targets[i]}\""
            done
        fi

        # 生成endpoint配置
        local endpoint_config="
        {
            \"listen\": \"${listen_ip}:${port_key}\",
            \"remote\": \"${main_target}\""

        # 添加extra_remotes（如果有多个目标）
        if [ -n "$extra_remotes" ]; then
            endpoint_config="$endpoint_config,
            \"extra_remotes\": [$extra_remotes]"
        fi

        # 添加负载均衡配置（如果有多个目标且设置了负载均衡）
        if [ -n "$extra_remotes" ] && [ -n "$balance_mode" ] && [ "$balance_mode" != "off" ]; then
            # 生成权重配置
            local weight_config=""
            local rule_weights="${port_weights[$port_key]}"

            if [ -n "$rule_weights" ]; then
                # 使用存储的权重（已在故障转移过滤中处理）
                weight_config=$(echo "$rule_weights" | sed 's/,/, /g')
            else
                # 使用默认相等权重
                for ((i=0; i<${#targets[@]}; i++)); do
                    if [ -n "$weight_config" ]; then
                        weight_config="$weight_config, "
                    fi
                    weight_config="${weight_config}1"
                done
            fi

            endpoint_config="$endpoint_config,
            \"balance\": \"$balance_mode: $weight_config\""
        fi

        # 添加through字段（仅中转服务器）
        local role="${port_roles[$port_key]:-1}"  # 使用存储的角色，默认为中转服务器
        if [ "$role" = "1" ] && [ -n "$through_ip" ] && [ "$through_ip" != "::" ]; then
            endpoint_config="$endpoint_config,
            \"through\": \"$through_ip\""
        fi

        # 添加传输配置 - 使用存储的规则角色信息
        local transport_config=$(get_transport_config "$security_level" "$tls_server_name" "$tls_cert_path" "$tls_key_path" "$role" "$WS_PATH")
        if [ -n "$transport_config" ]; then
            endpoint_config="$endpoint_config,
            $transport_config"
        fi

        # 添加MPTCP网络配置 - 从对应的规则文件读取MPTCP设置
        local mptcp_config=""
        local rule_file_for_port="${port_rule_files[$port_key]}"

        if [ -f "$rule_file_for_port" ]; then
            # 临时保存当前变量状态
            local saved_vars=$(declare -p RULE_ID RULE_NAME MPTCP_MODE 2>/dev/null || true)

            # 读取该端口对应的规则文件
            if read_rule_file "$rule_file_for_port"; then
                local mptcp_mode="${MPTCP_MODE:-off}"
                local send_mptcp="false"
                local accept_mptcp="false"

                case "$mptcp_mode" in
                    "send")
                        send_mptcp="true"
                        ;;
                    "accept")
                        accept_mptcp="true"
                        ;;
                    "both")
                        send_mptcp="true"
                        accept_mptcp="true"
                        ;;
                esac

                # 只有在需要MPTCP时才添加network配置
                if [ "$send_mptcp" = "true" ] || [ "$accept_mptcp" = "true" ]; then
                    mptcp_config=",
            \"network\": {
                \"send_mptcp\": $send_mptcp,
                \"accept_mptcp\": $accept_mptcp
            }"
                fi
            fi

            # 恢复变量状态（如果有保存的话）
            if [ -n "$saved_vars" ]; then
                eval "$saved_vars" 2>/dev/null || true
            fi
        fi

        # 添加Proxy网络配置 - 从对应的规则文件读取Proxy设置
        local proxy_config=""
        if [ -f "$rule_file_for_port" ]; then
            # 临时保存当前变量状态
            local saved_vars=$(declare -p RULE_ID RULE_NAME PROXY_MODE 2>/dev/null || true)

            # 读取该端口对应的规则文件
            if read_rule_file "$rule_file_for_port"; then
                local proxy_mode="${PROXY_MODE:-off}"
                local send_proxy="false"
                local accept_proxy="false"
                local send_proxy_version="2"

                case "$proxy_mode" in
                    "v1_send")
                        send_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v1_accept")
                        accept_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v1_both")
                        send_proxy="true"
                        accept_proxy="true"
                        send_proxy_version="1"
                        ;;
                    "v2_send")
                        send_proxy="true"
                        send_proxy_version="2"
                        ;;
                    "v2_accept")
                        accept_proxy="true"
                        send_proxy_version="2"
                        ;;
                    "v2_both")
                        send_proxy="true"
                        accept_proxy="true"
                        send_proxy_version="2"
                        ;;
                esac

                # 只有在需要Proxy时才添加配置
                if [ "$send_proxy" = "true" ] || [ "$accept_proxy" = "true" ]; then
                    local proxy_fields=""
                    if [ "$send_proxy" = "true" ]; then
                        proxy_fields="\"send_proxy\": $send_proxy,
                \"send_proxy_version\": $send_proxy_version"
                    fi
                    if [ "$accept_proxy" = "true" ]; then
                        if [ -n "$proxy_fields" ]; then
                            proxy_fields="$proxy_fields,
                \"accept_proxy\": $accept_proxy,
                \"accept_proxy_timeout\": 5"
                        else
                            proxy_fields="\"accept_proxy\": $accept_proxy,
                \"accept_proxy_timeout\": 5"
                        fi
                    fi

                    if [ -n "$mptcp_config" ]; then
                        # 如果已有MPTCP配置，在network内添加Proxy配置
                        proxy_config=",
                $proxy_fields"
                    else
                        # 如果没有MPTCP配置，创建新的network配置
                        proxy_config=",
            \"network\": {
                $proxy_fields
            }"
                    fi
                fi
            fi

            # 恢复变量状态（如果有保存的话）
            if [ -n "$saved_vars" ]; then
                eval "$saved_vars" 2>/dev/null || true
            fi
        fi

        # 合并MPTCP和Proxy配置
        local network_config=""
        if [ -n "$mptcp_config" ] && [ -n "$proxy_config" ]; then
            # 两者都有，合并到一个network块中
            network_config=$(echo "$mptcp_config" | sed 's/}//')
            network_config="$network_config$proxy_config
            }"
        elif [ -n "$mptcp_config" ]; then
            network_config="$mptcp_config"
        elif [ -n "$proxy_config" ]; then
            network_config="$proxy_config"
        fi

        endpoint_config="$endpoint_config$network_config
        }"

        endpoints="$endpoints$endpoint_config"
        count=$((count + 1))
    done

    echo "$endpoints"
}

# 生成 realm 配置文件 - 支持多规则和动态配置
generate_realm_config() {
    echo -e "${YELLOW}正在生成 Realm 配置文件...${NC}"

    # 创建配置目录和日志文件（内置日志管理）
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$(dirname "$LOG_PATH")"

    # 内置日志管理：创建前先清理过大的日志文件
    manage_log_size "$LOG_PATH" 50 25
    touch "$LOG_PATH" && chmod 644 "$LOG_PATH"

    # 初始化规则目录
    init_rules_dir

    # 检查是否有启用的规则
    local has_rules=false
    local enabled_count=0

    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    has_rules=true
                    enabled_count=$((enabled_count + 1))
                fi
            fi
        done
    fi

    # 如果没有启用的规则，生成空配置
    if [ "$has_rules" = false ]; then
        echo -e "${BLUE}未找到启用的规则，生成空配置${NC}"
        generate_complete_config ""
        echo -e "${GREEN}✓ 空配置文件已生成${NC}"
        return 0
    fi

    # 生成基于规则的配置
    echo -e "${BLUE}找到 $enabled_count 个启用的规则，生成多规则配置${NC}"

    # 获取所有启用规则的endpoints
    local endpoints=$(generate_endpoints_from_rules)

    # 使用统一模板生成多规则配置
    generate_complete_config "$endpoints"

    echo -e "${GREEN}✓ 多规则配置文件已生成${NC}"
    echo -e "${BLUE}配置详情: $enabled_count 个启用的转发规则${NC}"

    # 显示规则摘要
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                # 根据规则角色使用不同的字段
                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    local target_host="${FORWARD_TARGET%:*}"
                    local target_port="${FORWARD_TARGET##*:}"
                    local display_target=$(smart_display_target "$target_host")
                    local display_ip="::"
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                else
                    # 中转服务器使用REMOTE_HOST
                    local display_target=$(smart_display_target "$REMOTE_HOST")
                    local display_ip="${NAT_LISTEN_IP:-::}"
                    local through_display="${THROUGH_IP:-::}"
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                fi
            fi
        fi
    done
}

# 生成 systemd 服务文件 - 简化（内置日志管理）
generate_systemd_service() {
    echo -e "${YELLOW}正在生成 systemd 服务文件...${NC}"

    # 内置日志管理：启动前清理过大的日志文件
    manage_log_size "$LOG_PATH" 50 25

    # 直接生成systemd服务文件 - 使用简化的启动参数和日志限制
    cat > "$SYSTEMD_PATH" <<EOF
[Unit]
Description=Realm TCP Relay Service
Documentation=https://github.com/zywe03/realm-xwPF
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${REALM_PATH} -c ${CONFIG_PATH}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
RestartPreventExitStatus=23

# 资源限制优化
LimitNOFILE=1048576
LimitNPROC=1048576

# 安全设置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR} /var/log

# 内置日志限制（防止journal过大）
StandardOutput=journal
StandardError=journal
SyslogIdentifier=realm

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}✓ systemd 服务文件已生成${NC}"
    systemctl daemon-reload
    echo -e "${GREEN}✓ systemd 服务已重新加载${NC}"
}

# 简单启动空服务（让脚本能识别已安装状态）
start_empty_service() {
    echo -e "${YELLOW}正在初始化配置以完成安装...${NC}"

    # 创建最基本的配置目录
    mkdir -p "$CONFIG_DIR"

    # 创建最简单的空配置文件
    cat > "$CONFIG_PATH" <<EOF
{
    "endpoints": []
}
EOF

    # 创建 systemd 服务文件（必需的）
    generate_systemd_service

    # 启用并启动服务
    systemctl enable realm >/dev/null 2>&1
    systemctl start realm >/dev/null 2>&1
}

# 自安装脚本到系统
self_install() {
    echo -e "${YELLOW}正在安装脚本到系统...${NC}"

    local script_name="xwPF.sh"
    local install_dir="/usr/local/bin"
    local shortcut_name="pf"

    # 创建安装目录
    mkdir -p "$install_dir"

    # 检查系统目录是否已有脚本，优先执行更新逻辑
    if [ -f "${install_dir}/${script_name}" ]; then
        echo -e "${GREEN}✓ 检测到系统已安装脚本，正在更新...${NC}"

        # 自动从GitHub下载最新版本覆盖更新
        echo -e "${BLUE}正在从GitHub下载最新脚本...${NC}"
        local base_script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh"

        # 使用统一多源下载函数
        if download_from_sources "$base_script_url" "${install_dir}/${script_name}"; then
            chmod +x "${install_dir}/${script_name}"
        else
            echo -e "${RED}✗ 脚本更新失败，手动更新wget -qO- https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh | sudo bash -s install${NC}"
            echo -e "${BLUE}使用现有脚本版本${NC}"
        fi
    elif [ -f "$0" ]; then
        # 首次安装：复制脚本到系统目录
        cp "$0" "${install_dir}/${script_name}"
        chmod +x "${install_dir}/${script_name}"
        echo -e "${GREEN}✓ 脚本已安装到: ${install_dir}/${script_name}${NC}"
    else
        # 如果是通过管道运行的，需要重新下载
        echo -e "${BLUE}正在从GitHub下载脚本...${NC}"
        local base_script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/xwPF.sh"

        # 使用统一多源下载函数
        if download_from_sources "$base_script_url" "${install_dir}/${script_name}"; then
            chmod +x "${install_dir}/${script_name}"
        else
            echo -e "${RED}✗ 脚本下载失败${NC}"
            return 1
        fi
    fi

    # 创建快捷命令
    cat > "${install_dir}/${shortcut_name}" <<EOF
#!/bin/bash
# Realm 端口转发快捷启动脚本
# 优先检测当前目录的脚本，如果不存在则使用系统安装的脚本

# 检查当前目录是否有xwPF.sh
if [ -f "\$(pwd)/xwPF.sh" ]; then
    exec bash "\$(pwd)/xwPF.sh" "\$@"
else
    exec bash "${install_dir}/${script_name}" "\$@"
fi
EOF

    chmod +x "${install_dir}/${shortcut_name}"
    echo -e "${GREEN}✓ 快捷命令已创建: ${shortcut_name}${NC}"

    # 检查PATH
    if [[ ":$PATH:" != *":${install_dir}:"* ]]; then
        echo -e "${YELLOW}注意: ${install_dir} 不在 PATH 中${NC}"
        echo -e "${BLUE}建议将以下行添加到 ~/.bashrc:${NC}"
        echo -e "${GREEN}export PATH=\"\$PATH:${install_dir}\"${NC}"
        echo ""
    fi

    return 0
}

# 智能安装和配置流程
smart_install() {
    echo -e "${GREEN}=== xwPF Realm 一键脚本智能安装 $SCRIPT_VERSION ===${NC}"
    echo ""

    # 步骤1: 检测系统
    detect_system
    echo -e "${BLUE}检测到系统: ${GREEN}$OS $VER${NC}"
    echo ""

    # 步骤2: 安装依赖
    install_dependencies

    # 步骤3: 自安装脚本
    if ! self_install; then
        echo -e "${RED}脚本安装失败${NC}"
        exit 1
    fi

    echo -e "${GREEN}=== 脚本安装完成！ ===${NC}"
    echo ""

    # 步骤4: 下载最新的 realm 主程序
    if install_realm; then
        echo -e "${GREEN}=== 安装完成！ ===${NC}"
        echo -e "${YELLOW}输入快捷命令 ${GREEN}pf${YELLOW} 进入脚本交互界面${NC}"
    else
        echo -e "${RED}错误: realm安装失败${NC}"
        echo -e "${YELLOW}可能原因: 网络连接问题或所有下载源均不可用${NC}"
        echo -e "${BLUE}稍后重试或参考https://github.com/zywe03/realm-xwPF#离线安装${NC}"
        echo -e "${YELLOW}输入快捷命令 ${GREEN}pf${YELLOW} 可进入脚本交互界面${NC}"
    fi
}

# 服务管理 - 启动
service_start() {
    echo -e "${YELLOW}正在启动 Realm 服务...${NC}"

    if systemctl start realm; then
        echo -e "${GREEN}✓ Realm 服务启动成功${NC}"
    else
        echo -e "${RED}✗ Realm 服务启动失败${NC}"
        echo -e "${BLUE}查看详细错误信息:${NC}"
        systemctl status realm --no-pager -l
        return 1
    fi
}

# 服务管理 - 停止
service_stop() {
    echo -e "${YELLOW}正在停止 Realm 服务...${NC}"

    if systemctl stop realm; then
        echo -e "${GREEN}✓ Realm 服务已停止${NC}"
    else
        echo -e "${RED}✗ Realm 服务停止失败${NC}"
        return 1
    fi
}

# 服务管理 - 重启
service_restart() {
    echo -e "${YELLOW}正在重启 Realm 服务...${NC}"

    # 重新生成配置文件
    echo -e "${BLUE}重新生成配置文件...${NC}"
    generate_realm_config

    if systemctl restart realm; then
        echo -e "${GREEN}✓ Realm 服务重启成功${NC}"
    else
        echo -e "${RED}✗ Realm 服务重启失败${NC}"
        echo -e "${BLUE}查看详细错误信息:${NC}"
        systemctl status realm --no-pager -l
        return 1
    fi
}

# 服务管理 - 状态
service_status() {
    echo -e "${YELLOW}Realm 服务状态:${NC}"
    echo ""

    # 获取服务状态
    local status=$(systemctl is-active realm 2>/dev/null)
    local enabled=$(systemctl is-enabled realm 2>/dev/null)

    # 显示基本状态
    if [ "$status" = "active" ]; then
        echo -e "运行状态: ${GREEN}●${NC} 运行中"
    elif [ "$status" = "inactive" ]; then
        echo -e "运行状态: ${RED}●${NC} 已停止"
    elif [ "$status" = "failed" ]; then
        echo -e "运行状态: ${RED}●${NC} 运行失败"
    else
        echo -e "运行状态: ${YELLOW}●${NC} $status"
    fi

    if [ "$enabled" = "enabled" ]; then
        echo -e "开机启动: ${GREEN}已启用${NC}"
    else
        echo -e "开机启动: ${YELLOW}未启用${NC}"
    fi

    # 显示配置信息
    echo ""
    echo -e "${BLUE}配置信息:${NC}"

    # 检查是否有规则配置
    local has_rules=false
    local enabled_count=0

    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    has_rules=true
                    enabled_count=$((enabled_count + 1))
                fi
            fi
        done
    fi

    if [ "$has_rules" = true ]; then
        echo -e "配置模式: ${GREEN}多规则模式${NC}"
        echo -e "启用规则: ${GREEN}$enabled_count${NC} 个"
        echo ""
        echo -e "${BLUE}活跃规则列表:${NC}"

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    # 根据规则角色使用不同的字段
                    if [ "$RULE_ROLE" = "2" ]; then
                        # 落地服务器使用FORWARD_TARGET
                        local target_host="${FORWARD_TARGET%:*}"
                        local target_port="${FORWARD_TARGET##*:}"
                        local display_target=$(smart_display_target "$target_host")
                        local display_ip="::"
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                    else
                        # 中转服务器使用REMOTE_HOST
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local display_ip="${NAT_LISTEN_IP:-::}"
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                    fi
                    # 构建安全级别显示
                    local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                    local note_display=""
                    if [ -n "$RULE_NOTE" ]; then
                        note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                    fi
                    # 显示状态信息
                    get_rule_status_display "$security_display" "$note_display"

                fi
            fi
        done
    fi

    # 显示端口监听状态
    echo ""
    echo -e "${BLUE}端口监听状态:${NC}"

    # 使用 ss 命令检测端口（Debian/Ubuntu标准工具）
    local port_check_cmd="ss -tlnp"

    # 检查端口监听状态
    if [ "$has_rules" = true ]; then
        # 多规则模式：检查所有启用规则的端口
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    if [ "$RULE_ROLE" = "2" ]; then
                        local display_ip="::"
                    else
                        local display_ip="${NAT_LISTEN_IP:-::}"
                    fi
                    if $port_check_cmd 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${GREEN}正在监听${NC}"
                    else
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${RED}未监听${NC}"
                    fi
                fi
            fi
        done
    fi

    echo ""
    echo -e "${BLUE}详细状态信息:${NC}"
    systemctl status realm --no-pager -l
}

# 卸载函数
uninstall_realm() {
    echo -e "${RED}⚠️  警告: 即将分阶段卸载 Realm 端口转发服务${NC}"
    echo ""

    # 第一阶段：Realm 服务和配置
    echo -e "${YELLOW}=== 第一阶段：Realm 相关全部服务和配置文件 ===${NC}"
    read -p "确认删除 Realm 服务和配置？(y/n): " confirm_realm
    if [[ "$confirm_realm" =~ ^[Yy]$ ]]; then
        uninstall_realm_stage_one
        echo -e "${GREEN}✓ 第一阶段完成${NC}"
    else
        echo -e "${BLUE}第一阶段已取消${NC}"
        return 0
    fi

    echo ""
    # 第二阶段：脚本文件
    echo -e "${YELLOW}=== 第二阶段：xwPF 脚本相关全部文件 ===${NC}"
    read -p "确认删除脚本文件？(y/n): " confirm_script
    if [[ "$confirm_script" =~ ^[Yy]$ ]]; then
        uninstall_script_files
        echo -e "${GREEN}🗑️  完全卸载完成${NC}"
    else
        echo -e "${BLUE}脚本文件保留，可继续使用 pf 命令${NC}"
    fi
}

# 第一阶段：清理 Realm 相关
uninstall_realm_stage_one() {
    # 停止服务
    systemctl is-active realm >/dev/null 2>&1 && systemctl stop realm
    systemctl is-enabled realm >/dev/null 2>&1 && systemctl disable realm >/dev/null 2>&1
    stop_health_check_service
    pgrep "realm" >/dev/null 2>&1 && { pkill -f "realm"; sleep 2; pkill -9 -f "realm" 2>/dev/null; }

    # 清理文件 - 使用通用清理函数
    cleanup_files_by_paths "$REALM_PATH" "$CONFIG_DIR" "$SYSTEMD_PATH" "$LOG_PATH" "/etc/realm"
    cleanup_files_by_pattern "realm" "/var/log /tmp /var/tmp"

    # 清理系统配置
    [ -f "/etc/sysctl.d/90-enable-MPTCP.conf" ] && rm -f "/etc/sysctl.d/90-enable-MPTCP.conf"
    command -v ip >/dev/null 2>&1 && ip mptcp endpoint flush 2>/dev/null
    systemctl daemon-reload
}

# 第二阶段：清理脚本文件
uninstall_script_files() {
    # 清理 xwPF.sh 文件
    cleanup_files_by_pattern "xwPF.sh" "/"

    # 清理 pf 命令（验证后删除）
    local exec_dirs=("/usr/local/bin" "/usr/bin" "/bin" "/opt/bin" "/root/bin")
    for dir in "${exec_dirs[@]}"; do
        [ -f "$dir/pf" ] && grep -q "xwPF" "$dir/pf" 2>/dev/null && rm -f "$dir/pf"
        [ -L "$dir/pf" ] && [[ "$(readlink "$dir/pf" 2>/dev/null)" == *"xwPF"* ]] && rm -f "$dir/pf"
    done
}

# 通用文件路径清理函数
cleanup_files_by_paths() {
    for path in "$@"; do
        if [ -f "$path" ]; then
            rm -f "$path"
        elif [ -d "$path" ]; then
            rm -rf "$path"
        fi
    done
}

# 通用文件模式清理函数
cleanup_files_by_pattern() {
    local pattern="$1"
    local search_dirs="${2:-/}"

    IFS=' ' read -ra dirs_array <<< "$search_dirs"
    for dir in "${dirs_array[@]}"; do
        [ -d "$dir" ] && find "$dir" -name "*${pattern}*" -type f 2>/dev/null | while read -r file; do
            [ -f "$file" ] && rm -f "$file"
        done &
    done
    wait
}

# 批量清理日志文件
cleanup_log_files() {
    local pattern="$1"
    local search_dirs="${2:-/var/log /tmp /root /home /usr/local/var/log /opt}"

    IFS=' ' read -ra dirs_array <<< "$search_dirs"
    for log_dir in "${dirs_array[@]}"; do
        if [ -d "$log_dir" ]; then
            find "$log_dir" -name "*${pattern}*" -type f 2>/dev/null | while read -r file; do
                if [ -f "$file" ]; then
                    echo -e "${YELLOW}发现 ${pattern} 日志文件: $file${NC}"
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除日志文件: $file"
                fi
            done &
        fi
    done
    wait  # 等待所有并行搜索完成
}

# 统一的临时文件清理函数
cleanup_temp_files_by_pattern() {
    local pattern="$1"
    local search_dirs="${2:-/tmp /var/tmp /root /home /usr/local/tmp}"
    local exclude_paths="${3:-/realm/config /realm/rules}"  # 排除重要配置路径

    IFS=' ' read -ra dirs_array <<< "$search_dirs"
    for tmp_dir in "${dirs_array[@]}"; do
        if [ -d "$tmp_dir" ]; then
            find "$tmp_dir" -name "*${pattern}*" -type f 2>/dev/null | while read -r file; do
                if [ -f "$file" ]; then
                    # 检查是否在排除路径中
                    local should_exclude=false
                    IFS=' ' read -ra exclude_array <<< "$exclude_paths"
                    for exclude_path in "${exclude_array[@]}"; do
                        if [[ "$file" == *"$exclude_path"* ]]; then
                            should_exclude=true
                            break
                        fi
                    done

                    if [ "$should_exclude" = false ]; then
                        echo -e "${YELLOW}发现 ${pattern} 临时文件: $file${NC}"
                        rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除临时文件: $file"
                    fi
                fi
            done &
        fi
    done
    wait  # 等待所有并行搜索完成
}

# 查看当前配置
show_config() {
    echo -e "${YELLOW}=== 当前配置信息 ===${NC}"
    echo ""

    # 检查配置文件是否存在
    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${RED}配置文件不存在，请先运行安装配置${NC}"
        return 1
    fi

    # 显示配置文件路径
    echo -e "${BLUE}配置文件位置:${NC}"
    echo -e "  主配置: ${GREEN}$CONFIG_PATH${NC}"
    echo -e "  管理配置: ${GREEN}$MANAGER_CONF${NC}"
    echo -e "  规则目录: ${GREEN}$RULES_DIR${NC}"
    echo ""

    # 显示规则信息
    if [ -d "$RULES_DIR" ]; then
        local total_rules=0
        local enabled_rules=0

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                total_rules=$((total_rules + 1))
                if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ]; then
                    enabled_rules=$((enabled_rules + 1))
                fi
            fi
        done

        echo -e "${BLUE}规则统计:${NC}"
        echo -e "  总规则数: ${GREEN}$total_rules${NC}"
        echo -e "  启用规则: ${GREEN}$enabled_rules${NC}"
        echo -e "  禁用规则: ${YELLOW}$((total_rules - enabled_rules))${NC}"
        echo ""

        if [ $total_rules -gt 0 ]; then
            echo -e "${BLUE}规则详情:${NC}"
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file"; then
                        local status_color="${GREEN}"
                        local status_text="启用"
                        if [ "$ENABLED" != "true" ]; then
                            status_color="${RED}"
                            status_text="禁用"
                        fi

                        echo -e "  规则 $RULE_ID: ${status_color}$status_text${NC} - $RULE_NAME"
                        # 根据规则角色使用不同的字段
                        if [ "$RULE_ROLE" = "2" ]; then
                            # 落地服务器使用FORWARD_TARGET
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            local display_ip="::"
                            echo -e "    监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        else
                            # 中转服务器使用REMOTE_HOST
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local display_ip="${NAT_LISTEN_IP:-::}"
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "    中转: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        fi
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"
                        echo ""
                    fi
                fi
            done
        fi
    else
        echo -e "${BLUE}规则信息:${NC} 使用传统配置模式"
        echo ""
    fi


}

# 智能显示转发目标地址（处理本地地址和多地址）
smart_display_target() {
    local target="$1"

    # 处理多地址情况
    if [[ "$target" == *","* ]]; then
        # 分割多地址
        IFS=',' read -ra addresses <<< "$target"
        local display_addresses=()

        for addr in "${addresses[@]}"; do
            addr=$(echo "$addr" | xargs)  # 去除空格
            local display_addr="$addr"

            if [[ "$addr" == "127.0.0.1" ]] || [[ "$addr" == "localhost" ]]; then
                # IPv4本地地址时显示IPv4公网IP
                local public_ipv4=$(get_public_ip ipv4)
                if [ -n "$public_ipv4" ]; then
                    display_addr="$public_ipv4"
                fi
            elif [[ "$addr" == "::1" ]]; then
                # IPv6本地地址时显示IPv6公网IP
                local public_ipv6=$(get_public_ip ipv6)
                if [ -n "$public_ipv6" ]; then
                    display_addr="$public_ipv6"
                fi
            fi

            display_addresses+=("$display_addr")
        done

        # 重新组合地址
        local result=""
        for i in "${!display_addresses[@]}"; do
            if [ $i -gt 0 ]; then
                result="$result,"
            fi
            result="$result${display_addresses[i]}"
        done
        echo "$result"
    else
        # 单地址处理
        if [[ "$target" == "127.0.0.1" ]] || [[ "$target" == "localhost" ]]; then
            # IPv4本地地址时显示IPv4公网IP
            local public_ipv4=$(get_public_ip ipv4)
            if [ -n "$public_ipv4" ]; then
                echo "$public_ipv4"
            else
                echo "$target"
            fi
        elif [[ "$target" == "::1" ]]; then
            # IPv6本地地址时显示IPv6公网IP
            local public_ipv6=$(get_public_ip ipv6)
            if [ -n "$public_ipv6" ]; then
                echo "$public_ipv6"
            else
                echo "$target"
            fi
        else
            echo "$target"
        fi
    fi
}

# 显示简要状态信息（快速版本，避免网络请求）
show_brief_status() {
    echo ""
    echo -e "${BLUE}=== 当前状态 ===${NC}"

    # 检查 realm 二进制文件是否存在
    if [ ! -f "${REALM_PATH}" ] || [ ! -x "${REALM_PATH}" ]; then
        echo -e " Realm状态：${RED} 未安装 ${NC}"
        echo -e "${YELLOW}请选择 1. 安装(更新)程序,脚本 ${NC}"
        return
    fi

    # 检查配置文件是否存在
    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${YELLOW}=== 配置缺失 ===${NC}"
        echo -e "${BLUE}Realm 已安装但配置缺失，请运行 安装配置/添加配置 来初始化配置${NC}"
        return
    fi

    # 正常状态显示
    local status=$(systemctl is-active realm 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo -e "服务状态: ${GREEN}●${NC} 运行中"
    else
        echo -e "服务状态: ${RED}●${NC} 已停止"
    fi

    # 检查是否有多规则配置
    local has_rules=false
    local enabled_count=0
    local disabled_count=0
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file"; then
                    if [ "$ENABLED" = "true" ]; then
                        has_rules=true
                        enabled_count=$((enabled_count + 1))
                    else
                        disabled_count=$((disabled_count + 1))
                    fi
                fi
            fi
        done
    fi

    if [ "$has_rules" = true ] || [ "$disabled_count" -gt 0 ]; then
        # 多规则模式
        local total_count=$((enabled_count + disabled_count))
        echo -e "配置模式: ${GREEN}多规则模式${NC} (${GREEN}$enabled_count${NC} 启用 / ${YELLOW}$disabled_count${NC} 禁用 / 共 $total_count 个)"

        # 按服务器类型分组显示启用的规则
        if [ "$enabled_count" -gt 0 ]; then
            # 中转服务器规则
            local has_relay_rules=false
            local relay_count=0
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "1" ]; then
                        if [ "$has_relay_rules" = false ]; then
                            echo -e "${GREEN}中转服务器:${NC}"
                            has_relay_rules=true
                        fi
                        relay_count=$((relay_count + 1))
                        # 显示详细的转发配置信息
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local rule_display_name="$RULE_NAME"
                        local display_ip="${NAT_LISTEN_IP:-::}"
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"

                    fi
                fi
            done

            # 落地服务器规则
            local has_exit_rules=false
            local exit_count=0
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "true" ] && [ "$RULE_ROLE" = "2" ]; then
                        if [ "$has_exit_rules" = false ]; then
                            if [ "$has_relay_rules" = true ]; then
                                echo ""
                            fi
                            echo -e "${GREEN}落地服务器 (双端Realm架构):${NC}"
                            has_exit_rules=true
                        fi
                        exit_count=$((exit_count + 1))
                        # 显示详细的转发配置信息
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH" "$TLS_SERVER_NAME")
                        # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                        local target_host="${FORWARD_TARGET%:*}"
                        local target_port="${FORWARD_TARGET##*:}"
                        local display_target=$(smart_display_target "$target_host")
                        local rule_display_name="$RULE_NAME"
                        local display_ip="::"
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: ${GREEN}$RULE_NOTE${NC}"
                        fi
                        # 显示状态信息
                        get_rule_status_display "$security_display" "$note_display"

                    fi
                fi
            done
        fi

        # 显示禁用的规则（简要）
        if [ "$disabled_count" -gt 0 ]; then
            echo -e "${YELLOW}禁用的规则:${NC}"
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$ENABLED" = "false" ]; then
                        # 根据规则角色使用不同的字段
                        if [ "$RULE_ROLE" = "2" ]; then
                            # 落地服务器使用FORWARD_TARGET
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            echo -e "  • ${WHITE}$RULE_NAME${NC}: $LISTEN_PORT → $display_target:$target_port (已禁用)"
                        else
                            # 中转服务器使用REMOTE_HOST
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "  • ${WHITE}$RULE_NAME${NC}: $LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT (已禁用)"
                        fi
                    fi
                fi
            done
        fi
    else
        # 没有启用的规则
        echo -e "转发规则: ${YELLOW}暂无${NC} (可通过 '转发配置管理' 添加)"
    fi
    echo ""
}

# 获取安全级别显示文本
get_security_display() {
    local security_level="$1"
    local ws_path="$2"
    local tls_server_name="$3"

    case "$security_level" in
        "standard")
            echo "默认传输"
            ;;
        "ws")
            echo "WebSocket (路径: $ws_path)"
            ;;
        "tls_self")
            local display_sni="${tls_server_name:-$DEFAULT_SNI_DOMAIN}"
            echo "TLS自签证书 (SNI: $display_sni)"
            ;;
        "tls_ca")
            echo "TLS CA证书 (域名: $tls_server_name)"
            ;;
        "ws_tls_self")
            local display_sni="${tls_server_name:-$DEFAULT_SNI_DOMAIN}"
            echo "tls 自签证书+ws (SNI: $display_sni) (路径: $ws_path)"
            ;;
        "ws_tls_ca")
            echo "tls CA证书+ws (域名: $tls_server_name) (路径: $ws_path)"
            ;;
        "ws_"*)
            echo "$security_level (路径: $ws_path)"
            ;;
        *)
            echo "$security_level"
            ;;
    esac
}

# 获取GMT+8时间
get_gmt8_time() {
    TZ='GMT-8' date "$@"
}

# 下载中转网络链路测试脚本
download_speedtest_script() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/speedtest.sh"
    local target_path="/etc/realm/speedtest.sh"

    echo -e "${GREEN}正在下载最新版测速脚本...${NC}"

    # 创建目录
    mkdir -p "$(dirname "$target_path")"

    # 使用统一多源下载函数
    if download_from_sources "$script_url" "$target_path"; then
        chmod +x "$target_path"
        return 0
    else
        echo -e "${RED}请检查网络连接${NC}"
        return 1
    fi
}

# 中转网络链路测试菜单
speedtest_menu() {
    local speedtest_script="/etc/realm/speedtest.sh"

    # 每次都下载最新版本
    if ! download_speedtest_script; then
        echo -e "${RED}无法下载测速脚本，功能暂时不可用${NC}"
        read -p "按回车键返回主菜单..."
        return 1
    fi

    # 调用测速脚本
    echo -e "${BLUE}启动测速工具...${NC}"
    echo ""
    bash "$speedtest_script"

    # 返回后暂停
    echo ""
    read -p "按回车键返回主菜单..."
}

# 可视化菜单界面
show_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== xwPF Realm全功能一键脚本 $SCRIPT_VERSION ===${NC}"
        echo -e "${GREEN}作者主页:https://zywe.de${NC}"
        echo -e "${GREEN}项目开源:https://github.com/zywe03/realm-xwPF${NC}"
        echo -e "${GREEN}一个开箱即用、轻量可靠、灵活可控的 Realm 转发管理工具${NC}"
        echo -e "${GREEN}官方realm的全部功能+故障转移 | 快捷命令: pf${NC}"

        # 显示当前状态
        show_brief_status

        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 安装(更新)程序,脚本"
        echo -e "${BLUE}2.${NC} 转发配置管理"
        echo -e "${GREEN}3.${NC} 重启服务"
        echo -e "${GREEN}4.${NC} 停止服务"
        echo -e "${GREEN}5.${NC} 查看日志"
        echo -e "${BLUE}6.${NC} 中转网络链路测试"
        echo -e "${RED}7.${NC} 卸载服务"
        echo -e "${YELLOW}0.${NC} 退出"
        echo ""

        read -p "请输入选择 [0-7]: " choice
        echo ""

        case $choice in
            1)
                smart_install
                exit 0
                ;;
            2)
                check_dependencies
                rules_management_menu
                ;;
            3)
                check_dependencies
                service_restart
                read -p "按回车键继续..."
                ;;
            4)
                check_dependencies
                service_stop
                read -p "按回车键继续..."
                ;;
            5)
                check_dependencies
                echo -e "${YELLOW}实时查看 Realm 日志 (按 Ctrl+C 返回菜单):${NC}"
                echo ""
                journalctl -u realm -f --no-pager
                ;;
            6)
                check_dependencies
                speedtest_menu
                ;;
            7)
                check_dependencies
                uninstall_realm
                read -p "按回车键继续..."
                ;;
            0)
                echo -e "${BLUE}感谢使用xwPF 网络转发管理脚本！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 0-7${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 内置清理机制
cleanup_temp_files() {
    # 清理过期的路径缓存（超过24小时）
    local cache_file="/tmp/realm_path_cache"
    if [ -f "$cache_file" ]; then
        local cache_age=$(( $(date +%s) - $(stat -f%m "$cache_file" 2>/dev/null || stat -c%Y "$cache_file" 2>/dev/null || echo 0) ))
        if [ "$cache_age" -gt 604800 ]; then  # 7天
            rm -f "$cache_file"
        fi
    fi

    # 清理配置更新标记文件（仅清理过期的）
    local update_file="/tmp/realm_config_update_needed"
    if [ -f "$update_file" ]; then
        local file_age=$(( $(date +%s) - $(stat -f%m "$update_file" 2>/dev/null || stat -c%Y "$update_file" 2>/dev/null || echo 0) ))
        if [ "$file_age" -gt 300 ]; then  # 5分钟过期
            rm -f "$update_file" 2>/dev/null
        fi
    fi

    # 安全清理超过1小时的realm临时文件（避免误删）
    find /tmp -name "*realm*" -type f -mmin +60 2>/dev/null | while read -r file; do
        # 确保是realm相关的临时文件，不是重要配置
        if [[ "$file" != *"/realm/config"* ]] && [[ "$file" != *"/realm/rules"* ]]; then
            rm -f "$file" 2>/dev/null
        fi
    done
}

# ---- 主逻辑 ----
main() {
    # 内置清理：启动时清理临时文件
    cleanup_temp_files

    # 检查特殊参数
    if [ "$1" = "--generate-config-only" ]; then
        # 只生成配置文件，不显示菜单
        generate_realm_config
        exit 0
    fi

    check_root

    case "$1" in
        install)
            # 安装模式：自动安装依赖和脚本
            smart_install
            ;;
        *)
            # 默认显示菜单界面
            show_menu
            ;;
    esac
}

# 故障转移切换功能（按端口分组管理）
toggle_failover_mode() {
    while true; do
        clear
        echo -e "${YELLOW}=== 开启/关闭故障转移 ===${NC}"
        echo ""

        # 按端口分组收集启用负载均衡的中转服务器规则
        # 清空并重新初始化关联数组
        unset port_groups port_configs port_failover_status
        declare -A port_groups
        declare -A port_configs
        declare -A port_failover_status

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$BALANCE_MODE" != "off" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（使用第一个规则的配置作为基准）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_failover_status[$port_key]="${FAILOVER_ENABLED:-false}"
                    fi

                    # 正确处理REMOTE_HOST中可能包含多个地址的情况
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        # REMOTE_HOST包含多个地址，分别添加
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            # 检查是否已存在，避免重复添加
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        # REMOTE_HOST是单个地址
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        # 检查是否已存在，避免重复添加
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 检查是否有负载均衡规则组（只显示有多个目标的规则组）
        local has_balance_rules=false
        declare -a rule_ports
        declare -a rule_names

        if [ ${#port_groups[@]} -gt 0 ]; then
            echo -e "${BLUE}当前负载均衡规则组:${NC}"
            echo ""

            for port_key in $(printf '%s\n' "${!port_groups[@]}" | sort -n); do
                # 计算目标服务器数量
                IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
                local target_count=${#targets[@]}

                # 只显示有多个目标服务器的规则组（故障转移的前提条件）
                if [ $target_count -gt 1 ]; then
                    if [ "$has_balance_rules" = false ]; then
                        has_balance_rules=true
                    fi

                    # 使用数字ID
                    local rule_number=$((${#rule_ports[@]} + 1))
                    rule_ports+=("$port_key")
                    rule_names+=("${port_configs[$port_key]}")

                    # 获取故障转移状态
                    local failover_status="${port_failover_status[$port_key]}"
                    local status_text="关闭"
                    local status_color="${RED}"

                    if [ "$failover_status" = "true" ]; then
                        status_text="开启"
                        status_color="${GREEN}"
                    fi

                    echo -e "${GREEN}$rule_number.${NC} ${port_configs[$port_key]} (端口: $port_key) - $target_count个目标服务器 - 故障转移: ${status_color}$status_text${NC}"
                fi
            done
        fi

        if [ "$has_balance_rules" = false ]; then
            echo -e "${YELLOW}暂无启用负载均衡的规则组${NC}"
            echo -e "${BLUE}提示: 只有开启负载均衡才能使用故障转移功能${NC}"
            echo ""
            echo -e "${BLUE}故障转移的前提条件：${NC}"
            echo -e "${BLUE}  1. 规则类型为中转服务器${NC}"
            echo -e "${BLUE}  2. 已启用负载均衡模式（轮询或IP哈希）${NC}"
            echo -e "${BLUE}  3. 有多个目标服务器${NC}"
            echo ""
            echo -e "${YELLOW}如果您有多目标规则但未启用负载均衡：${NC}"
            echo -e "${BLUE}  请先到 '1. 切换负载均衡模式' 开启负载均衡${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${WHITE}注意: 故障转移功能会自动检测节点健康状态并动态调整负载均衡${NC}"
        echo ""
        read -p "请输入规则编号 [1-${#rule_ports[@]}] (或按回车返回): " choice

        if [ -z "$choice" ]; then
            return
        fi

        # 验证数字输入
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#rule_ports[@]} ]; then
            echo -e "${RED}无效的规则编号${NC}"
            read -p "按回车键继续..."
            continue
        fi

        # 计算数组索引（从0开始）
        local selected_index=$((choice - 1))
        local selected_port="${rule_ports[$selected_index]}"
        local rule_name="${rule_names[$selected_index]}"

        # 切换故障转移状态
        local current_status="${port_failover_status[$selected_port]}"
        local new_status="true"
        local action_text="开启"
        local color="${GREEN}"

        if [ "$current_status" = "true" ]; then
            new_status="false"
            action_text="关闭"
            color="${RED}"
        fi

        # 直接切换状态，无需确认
        echo -e "${BLUE}正在${action_text}故障转移功能...${NC}"

        # 更新所有相关规则文件
        local updated_count=0
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$selected_port" ]; then
                    # 更新故障转移状态
                    if grep -q "^FAILOVER_ENABLED=" "$rule_file"; then
                        sed -i "s/^FAILOVER_ENABLED=.*/FAILOVER_ENABLED=\"$new_status\"/" "$rule_file"
                    else
                        echo "FAILOVER_ENABLED=\"$new_status\"" >> "$rule_file"
                    fi
                    updated_count=$((updated_count + 1))
                fi
            fi
        done

        echo -e "${color}✓ 已更新 $updated_count 个规则文件的故障转移状态${NC}"

        if [ "$new_status" = "true" ]; then
            echo -e "${BLUE}故障转移参数:${NC}"
            echo -e "  检查间隔: ${GREEN}4秒${NC}"
            echo -e "  失败阈值: ${GREEN}连续2次${NC}"
            echo -e "  成功阈值: ${GREEN}连续2次${NC}"
            echo -e "  连接超时: ${GREEN}3秒${NC}"
            echo -e "  恢复冷却: ${GREEN}120秒${NC}"
        fi

        # 重启服务以应用更改
        echo -e "${YELLOW}正在重启服务以应用故障转移设置...${NC}"
        service_restart

        # 管理健康检查服务
        if [ "$new_status" = "true" ]; then
            echo -e "${BLUE}正在启动健康检查服务...${NC}"
            start_health_check_service
        else
            # 检查是否还有其他规则启用了故障转移
            local has_other_failover=false
            for rule_file in "${RULES_DIR}"/rule-*.conf; do
                if [ -f "$rule_file" ]; then
                    if read_rule_file "$rule_file" && [ "$FAILOVER_ENABLED" = "true" ]; then
                        has_other_failover=true
                        break
                    fi
                fi
            done

            if [ "$has_other_failover" = false ]; then
                echo -e "${BLUE}正在停止健康检查服务...${NC}"
                stop_health_check_service
            fi
        fi

        echo -e "${GREEN}✓ 故障转移设置已生效${NC}"
        echo ""
        read -p "按回车键继续..."
        # 重新显示菜单以显示更新的状态
        continue
    done
}

# 配置监控服务管理
create_config_monitor_service() {
    local monitor_service="/etc/systemd/system/realm-config-monitor.service"
    local monitor_script="/etc/realm/health/config_monitor.sh"

    # 创建配置监控脚本
    cat > "$monitor_script" << 'EOF'
#!/bin/bash

# 配置监控脚本 - 使用inotify监控配置更新请求
MONITOR_FILE="/tmp/realm_config_update_needed"
CONFIG_FILE="/etc/realm/config.json"

# 查找主脚本 - 统一的多线程搜索逻辑
find_main_script() {
    local cache_file="/tmp/realm_path_cache"

    # 第一阶段：检查缓存
    if [ -f "$cache_file" ]; then
        cached_path=$(cat "$cache_file" 2>/dev/null)
        if [ -f "$cached_path" ]; then
            echo "$cached_path"
            return 0
        fi
    fi

    # 第二阶段：常见位置直接检查
    local common_paths=(
        "/usr/local/bin/pf"
        "/usr/local/bin/xwPF.sh"
        "/root/xwPF.sh"
        "/opt/xwPF.sh"
        "/usr/bin/xwPF.sh"
        "/usr/sbin/xwPF.sh"
    )

    for path in "${common_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path" > "$cache_file"
            echo "$path"
            return 0
        fi
    done

    # 第三阶段：分区域限制深度搜索
    local search_dirs=("/etc" "/var" "/opt" "/usr" "/home" "/root")
    for dir in "${search_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local found_path=$(timeout 30 find "$dir" -maxdepth 4 -name "xwPF.sh" -type f 2>/dev/null | head -1)
            if [ -n "$found_path" ] && [ -f "$found_path" ]; then
                echo "$found_path" > "$cache_file"
                echo "$found_path"
                return 0
            fi
        fi
    done

    # 第四阶段：全系统搜索
    local found_path=$(timeout 60 find / -name "xwPF.sh" -type f 2>/dev/null | head -1)
    if [ -n "$found_path" ] && [ -f "$found_path" ]; then
        echo "$found_path" > "$cache_file"
        echo "$found_path"
        return 0
    fi

    return 1
}

# 主循环
while true; do
    # 等待配置更新请求
    if command -v inotifywait >/dev/null 2>&1; then
        # 使用inotify监控
        inotifywait -e create -e moved_to /tmp/ 2>/dev/null | while read path action file; do
            if [ "$file" = "realm_config_update_needed" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 检测到配置更新请求"

                # 查找主脚本
                script_path=$(find_main_script)

                if [ -n "$script_path" ] && [ -f "$script_path" ]; then
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 正在重新生成配置..."

                    # 重新生成配置（直接调用脚本的配置生成功能）
                    "$script_path" --generate-config-only >/dev/null 2>&1

                    if [ -f "$CONFIG_FILE" ]; then
                        echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 正在重启realm服务..."
                        systemctl restart realm >/dev/null 2>&1

                        if [ $? -eq 0 ]; then
                            echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 配置更新成功"
                        else
                            echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 服务重启失败"
                        fi
                    else
                        echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 配置生成失败"
                    fi
                else
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 无法找到主脚本"
                fi

                # 删除标记文件
                rm -f "$MONITOR_FILE"
            fi
        done
    else
        # 轮询检查
        if [ -f "$MONITOR_FILE" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 检测到配置更新请求"

            # 查找主脚本
            script_path=$(find_main_script)

            if [ -n "$script_path" ] && [ -f "$script_path" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 正在重新生成配置..."

                # 重新生成配置（直接调用脚本的配置生成功能）
                "$script_path" --generate-config-only >/dev/null 2>&1

                if [ -f "$CONFIG_FILE" ]; then
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 正在重启realm服务..."
                    systemctl restart realm >/dev/null 2>&1

                    if [ $? -eq 0 ]; then
                        echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 配置更新成功"
                    else
                        echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 服务重启失败"
                    fi
                else
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 配置生成失败"
                fi
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') [MONITOR] 无法找到主脚本"
            fi

            # 删除标记文件
            rm -f "$MONITOR_FILE"
        fi

        sleep 2
    fi
done
EOF

    chmod +x "$monitor_script"

    # 创建systemd服务文件
    cat > "$monitor_service" << EOF
[Unit]
Description=Realm Configuration Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=$monitor_script
User=root
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=realm-config-monitor

[Install]
WantedBy=multi-user.target
EOF
}

# 健康检查服务管理
start_health_check_service() {
    local health_dir="/etc/realm/health"
    local health_script="/etc/realm/health/health_check.sh"
    local health_timer="/etc/systemd/system/realm-health-check.timer"
    local health_service="/etc/systemd/system/realm-health-check.service"

    # 创建健康检查目录
    mkdir -p "$health_dir"

    # 创建健康检查脚本
    cat > "$health_script" << 'EOF'
#!/bin/bash

# 健康检查脚本
HEALTH_DIR="/etc/realm/health"
RULES_DIR="/etc/realm/rules"
LOCK_FILE="/var/lock/realm-health-check.lock"

# 查找健康状态文件
HEALTH_STATUS_FILE=""
for path in "/etc/realm/health/health_status.conf" "/etc/realm/health_status.conf" "/var/lib/realm/health_status.conf"; do
    if [ -f "$path" ]; then
        HEALTH_STATUS_FILE="$path"
        break
    fi
done

# 如果找不到，使用默认路径
if [ -z "$HEALTH_STATUS_FILE" ]; then
    HEALTH_STATUS_FILE="$HEALTH_DIR/health_status.conf"
fi

# 获取文件锁
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 健康检查已在运行中，跳过本次检查"
    exit 0
fi

# 健康检查函数（统一使用check_connectivity）
check_connectivity() {
    local target="$1"
    local port="$2"
    local timeout="${3:-3}"

    # 使用nc检测连通性（netcat-openbsd已确保安装）
    nc -z -w"$timeout" "$target" "$port" >/dev/null 2>&1
    return $?
}

# 健康检查脚本专用的读取规则文件函数
read_rule_file_for_health_check() {
    local rule_file="$1"
    if [ ! -f "$rule_file" ]; then
        return 1
    fi

    # 清空变量
    unset RULE_ID RULE_NAME RULE_ROLE LISTEN_PORT LISTEN_IP THROUGH_IP REMOTE_HOST REMOTE_PORT
    unset FORWARD_TARGET SECURITY_LEVEL
    unset TLS_SERVER_NAME TLS_CERT_PATH TLS_KEY_PATH WS_PATH
    unset ENABLED BALANCE_MODE FAILOVER_ENABLED HEALTH_CHECK_INTERVAL
    unset FAILURE_THRESHOLD SUCCESS_THRESHOLD CONNECTION_TIMEOUT
    unset TARGET_STATES WEIGHTS CREATED_TIME

    # 读取配置
    source "$rule_file"
    return 0
}



# 初始化健康状态文件
if [ ! -f "$HEALTH_STATUS_FILE" ]; then
    echo "# Realm健康状态文件" > "$HEALTH_STATUS_FILE"
    echo "# 格式: RULE_ID|TARGET|STATUS|FAIL_COUNT|SUCCESS_COUNT|LAST_CHECK|FAILURE_START_TIME" >> "$HEALTH_STATUS_FILE"
fi

# 检查所有启用故障转移的规则
config_changed=false
current_time=$(date +%s)

for rule_file in "$RULES_DIR"/rule-*.conf; do
    if [ ! -f "$rule_file" ]; then
        continue
    fi

    if ! read_rule_file_for_health_check "$rule_file"; then
        continue
    fi

    # 只检查启用故障转移的中转规则
    if [ "$RULE_ROLE" != "1" ] || [ "$ENABLED" != "true" ] || [ "$FAILOVER_ENABLED" != "true" ]; then
        continue
    fi

    # 解析目标服务器
    if [[ "$REMOTE_HOST" == *","* ]]; then
        IFS=',' read -ra targets <<< "$REMOTE_HOST"
    else
        targets=("$REMOTE_HOST")
    fi

    # 检查每个目标
    for target in "${targets[@]}"; do
        target=$(echo "$target" | xargs)  # 去除空格
        target_key="${RULE_ID}|${target}"

        # 获取当前状态
        status_line=$(grep "^${target_key}|" "$HEALTH_STATUS_FILE" 2>/dev/null)
        if [ -n "$status_line" ]; then
            IFS='|' read -r _ _ status fail_count success_count last_check failure_start_time <<< "$status_line"
            # 兼容旧格式（没有failure_start_time字段）
            if [ -z "$failure_start_time" ]; then
                failure_start_time="$last_check"
            fi
        else
            status="healthy"
            fail_count=0
            success_count=2
            last_check=0
            failure_start_time=0
        fi

        # 执行健康检查
        if check_connectivity "$target" "$REMOTE_PORT" "${CONNECTION_TIMEOUT:-3}"; then
            # 检查成功
            success_count=$((success_count + 1))
            fail_count=0

            # 如果之前是故障状态，检查是否可以恢复
            if [ "$status" = "failed" ] && [ "$success_count" -ge "${SUCCESS_THRESHOLD:-2}" ]; then
                # 检查冷却期（基于故障开始时间）
                cooldown_period=$((120))  # 120秒冷却期
                if [ $((current_time - failure_start_time)) -ge "$cooldown_period" ]; then
                    status="healthy"
                    config_changed=true
                    failure_start_time=0  # 重置故障开始时间
                    echo "$(date '+%Y-%m-%d %H:%M:%S') [RECOVERY] 目标 $target:$REMOTE_PORT 已恢复健康"
                fi
            fi
        else
            # 检查失败
            fail_count=$((fail_count + 1))
            success_count=0

            # 如果连续失败达到阈值，标记为故障
            if [ "$status" = "healthy" ] && [ "$fail_count" -ge "${FAILURE_THRESHOLD:-2}" ]; then
                status="failed"
                config_changed=true
                failure_start_time="$current_time"  # 记录故障开始时间
                echo "$(date '+%Y-%m-%d %H:%M:%S') [FAILURE] 目标 $target:$REMOTE_PORT 已标记为故障"
            fi
        fi

        # 更新状态文件（包含故障开始时间）
        grep -v "^${target_key}|" "$HEALTH_STATUS_FILE" > "$HEALTH_STATUS_FILE.tmp" 2>/dev/null || true
        echo "${target_key}|${status}|${fail_count}|${success_count}|${current_time}|${failure_start_time}" >> "$HEALTH_STATUS_FILE.tmp"
        mv "$HEALTH_STATUS_FILE.tmp" "$HEALTH_STATUS_FILE"
    done
done

# 如果配置有变化，重新生成配置并重启服务
if [ "$config_changed" = true ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CONFIG] 检测到节点状态变化，正在更新配置..."

    # 查找主脚本
    script_path=""
    cache_file="/tmp/realm_path_cache"

    # 第一阶段：检查缓存
    if [ -f "$cache_file" ]; then
        cached_path=$(cat "$cache_file" 2>/dev/null)
        if [ -f "$cached_path" ]; then
            script_path="$cached_path"
        fi
    fi

    # 第二阶段：常见位置直接检查
    if [ -z "$script_path" ]; then
        common_paths=(
            "/usr/local/bin/pf"
            "/usr/local/bin/xwPF.sh"
            "/root/xwPF.sh"
            "/opt/xwPF.sh"
            "/usr/bin/xwPF.sh"
            "/usr/sbin/xwPF.sh"
        )

        for path in "${common_paths[@]}"; do
            if [ -f "$path" ]; then
                echo "$path" > "$cache_file"
                script_path="$path"
                break
            fi
        done
    fi

    # 第三阶段：分区域限制深度搜索
    if [ -z "$script_path" ]; then
        search_dirs=("/etc" "/var" "/opt" "/usr" "/home" "/root")
        for dir in "${search_dirs[@]}"; do
            if [ -d "$dir" ]; then
                found_path=$(timeout 30 find "$dir" -maxdepth 4 -name "xwPF.sh" -type f 2>/dev/null | head -1)
                if [ -n "$found_path" ] && [ -f "$found_path" ]; then
                    echo "$found_path" > "$cache_file"
                    script_path="$found_path"
                    break
                fi
            fi
        done
    fi

    # 第四阶段：全系统搜索
    if [ -z "$script_path" ]; then
        found_path=$(timeout 60 find / -name "xwPF.sh" -type f 2>/dev/null | head -1)
        if [ -n "$found_path" ] && [ -f "$found_path" ]; then
            echo "$found_path" > "$cache_file"
            script_path="$found_path"
        fi
    fi

    # 验证是否找到脚本路径
    if [ -z "$script_path" ] || [ ! -f "$script_path" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] 无法找到主脚本，跳过配置更新"
        exit 1
    fi

    # 创建配置更新标记文件，让inotify服务处理
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CONFIG] 标记配置需要更新..."
    # 先删除可能存在的文件，然后创建新文件，确保触发inotify事件
    rm -f /tmp/realm_config_update_needed
    echo "$(date '+%Y-%m-%d %H:%M:%S')" > /tmp/realm_config_update_needed

    # 等待配置更新完成（最多30秒）
    wait_count=0
    while [ -f "/tmp/realm_config_update_needed" ] && [ $wait_count -lt 30 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if [ -f "/tmp/realm_config_update_needed" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] 配置更新超时，可能需要手动处理"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [CONFIG] 配置更新完成"
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') [CONFIG] 配置更新完成"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] 健康检查完成"
EOF

    chmod +x "$health_script"

    # 创建systemd服务文件
    cat > "$health_service" << EOF
[Unit]
Description=Realm Health Check Service
After=network.target

[Service]
Type=oneshot
ExecStart=$health_script
User=root
WorkingDirectory=/etc/realm
StandardOutput=journal
StandardError=journal
SyslogIdentifier=realm-health

[Install]
WantedBy=multi-user.target
EOF

    # 创建systemd定时器
    cat > "$health_timer" << EOF
[Unit]
Description=Realm Health Check Timer
Requires=realm-health-check.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=4s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

    # 创建配置监控服务
    create_config_monitor_service

    # 启用并启动定时器
    systemctl daemon-reload
    systemctl enable realm-health-check.timer >/dev/null 2>&1
    systemctl start realm-health-check.timer >/dev/null 2>&1
    systemctl enable realm-config-monitor.service >/dev/null 2>&1
    systemctl start realm-config-monitor.service >/dev/null 2>&1

    echo -e "${GREEN}✓ 健康检查服务已启动${NC}"
}

stop_health_check_service() {
    # 停止并禁用定时器
    systemctl stop realm-health-check.timer >/dev/null 2>&1
    systemctl disable realm-health-check.timer >/dev/null 2>&1

    # 停止并禁用配置监控服务
    systemctl stop realm-config-monitor.service >/dev/null 2>&1
    systemctl disable realm-config-monitor.service >/dev/null 2>&1

    # 删除服务文件
    rm -f "/etc/systemd/system/realm-health-check.timer"
    rm -f "/etc/systemd/system/realm-health-check.service"
    rm -f "/etc/systemd/system/realm-config-monitor.service"
    rm -f "/etc/realm/health/config_monitor.sh"

    systemctl daemon-reload

    echo -e "${GREEN}✓ 健康检查服务已停止${NC}"
}

# 权重配置管理菜单
weight_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 权重配置管理 ===${NC}"
        echo ""

        # 按端口分组收集启用负载均衡的中转服务器规则
        declare -A port_groups
        declare -A port_configs
        declare -A port_weights
        declare -A port_balance_modes

        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$BALANCE_MODE" != "off" ]; then
                    local port_key="$LISTEN_PORT"

                    # 存储端口配置（优先使用包含完整权重的规则）
                    if [ -z "${port_configs[$port_key]}" ]; then
                        port_configs[$port_key]="$RULE_NAME"
                        port_weights[$port_key]="$WEIGHTS"
                        port_balance_modes[$port_key]="$BALANCE_MODE"
                    elif [[ "$WEIGHTS" == *","* ]] && [[ "${port_weights[$port_key]}" != *","* ]]; then
                        # 如果当前规则有完整权重而已存储的没有，更新为完整权重
                        port_weights[$port_key]="$WEIGHTS"
                    fi

                    # 正确处理REMOTE_HOST中可能包含多个地址的情况
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        # REMOTE_HOST包含多个地址，分别添加
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        for host in "${host_array[@]}"; do
                            local target="$host:$REMOTE_PORT"
                            # 检查是否已存在，避免重复添加
                            if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                                if [ -z "${port_groups[$port_key]}" ]; then
                                    port_groups[$port_key]="$target"
                                else
                                    port_groups[$port_key]="${port_groups[$port_key]},$target"
                                fi
                            fi
                        done
                    else
                        # REMOTE_HOST是单个地址
                        local target="$REMOTE_HOST:$REMOTE_PORT"
                        # 检查是否已存在，避免重复添加
                        if [[ "${port_groups[$port_key]}" != *"$target"* ]]; then
                            if [ -z "${port_groups[$port_key]}" ]; then
                                port_groups[$port_key]="$target"
                            else
                                port_groups[$port_key]="${port_groups[$port_key]},$target"
                            fi
                        fi
                    fi
                fi
            fi
        done

        # 检查是否有需要权重配置的端口组（多目标服务器）
        local has_balance_rules=false
        local rule_ports=()
        local rule_names=()

        for port_key in "${!port_groups[@]}"; do
            # 计算目标服务器总数
            IFS=',' read -ra targets <<< "${port_groups[$port_key]}"
            local target_count=${#targets[@]}

            # 只显示有多个目标服务器的端口组
            if [ "$target_count" -gt 1 ]; then
                if [ "$has_balance_rules" = false ]; then
                    echo "请选择要配置权重的规则组 (仅显示多目标服务器的负载均衡规则):"
                    has_balance_rules=true
                fi

                # 使用数字ID
                local rule_number=$((${#rule_ports[@]} + 1))
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")

                local balance_mode="${port_balance_modes[$port_key]}"
                echo -e "${GREEN}$rule_number.${NC} ${port_configs[$port_key]} (端口: $port_key) [$balance_mode] - $target_count个目标服务器"
            fi
        done

        if [ "$has_balance_rules" = false ]; then
            echo -e "${YELLOW}暂无需要权重配置的规则组${NC}"
            echo ""
            echo -e "${BLUE}权重配置的前提条件：${NC}"
            echo -e "  1. 必须是中转服务器规则"
            echo -e "  2. 必须已启用负载均衡模式 (roundrobin/iphash)"
            echo -e "  3. 必须有多个目标服务器"
            echo ""
            echo -e "${YELLOW}如果您有多目标规则但未启用负载均衡：${NC}"
            echo -e "  请先选择 '切换负载均衡模式' 启用负载均衡，然后再配置权重"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo -e "${GRAY}注意: 只有多个目标服务器的规则组才需要权重配置${NC}"
        echo ""
        read -p "请输入规则编号 [1-${#rule_ports[@]}] (或按回车返回): " selected_number

        if [ -z "$selected_number" ]; then
            break
        fi

        # 验证数字输入
        if ! [[ "$selected_number" =~ ^[0-9]+$ ]] || [ "$selected_number" -lt 1 ] || [ "$selected_number" -gt ${#rule_ports[@]} ]; then
            echo -e "${RED}无效的规则编号${NC}"
            read -p "按回车键继续..."
            continue
        fi

        # 计算数组索引（从0开始）
        local selected_index=$((selected_number - 1))

        # 配置选中端口组的权重
        local selected_port="${rule_ports[$selected_index]}"
        local selected_name="${rule_names[$selected_index]}"
        configure_port_group_weights "$selected_port" "$selected_name" "${port_groups[$selected_port]}" "${port_weights[$selected_port]}"
    done
}

# 配置端口组权重
configure_port_group_weights() {
    local port="$1"
    local rule_name="$2"
    local targets_str="$3"
    local current_weights_str="$4"

    clear
    echo -e "${GREEN}=== 权重配置: $rule_name ===${NC}"
    echo ""

    # 解析目标服务器
    IFS=',' read -ra targets <<< "$targets_str"
    local target_count=${#targets[@]}

    echo "规则组: $rule_name (端口: $port)"
    echo "目标服务器列表:"

    # 解析当前权重
    local current_weights
    if [ -n "$current_weights_str" ]; then
        IFS=',' read -ra current_weights <<< "$current_weights_str"
    else
        # 默认相等权重
        for ((i=0; i<target_count; i++)); do
            current_weights[i]=1
        done
    fi

    # 显示当前配置
    for ((i=0; i<target_count; i++)); do
        local weight="${current_weights[i]:-1}"
        echo -e "  $((i+1)). ${targets[i]} [当前权重: $weight]"
    done

    echo ""
    echo "请输入权重序列 (用逗号分隔):"
    echo -e "${WHITE}格式说明: 按服务器顺序输入权重值，如 \"2,1,3\"${NC}"
    echo -e "${WHITE}权重范围: 1-10，数值越大分配流量越多${NC}"
    echo ""

    read -p "权重序列: " weight_input

    if [ -z "$weight_input" ]; then
        echo -e "${YELLOW}未输入权重，保持原配置${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 验证权重输入
    if ! validate_weight_input "$weight_input" "$target_count"; then
        read -p "按回车键返回..."
        return
    fi

    # 预览配置
    preview_port_group_weight_config "$port" "$rule_name" "$weight_input" "${targets[@]}"
}

# 验证权重输入
validate_weight_input() {
    local weight_input="$1"
    local expected_count="$2"

    # 检查格式
    if ! [[ "$weight_input" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        echo -e "${RED}权重格式错误，请使用数字和逗号，如: 2,1,3${NC}"
        return 1
    fi

    # 解析权重数组
    IFS=',' read -ra weights <<< "$weight_input"

    # 检查数量
    if [ "${#weights[@]}" -ne "$expected_count" ]; then
        echo -e "${RED}权重数量不匹配，需要 $expected_count 个权重值，实际输入 ${#weights[@]} 个${NC}"
        return 1
    fi

    # 检查权重值范围
    for weight in "${weights[@]}"; do
        if [ "$weight" -lt 1 ] || [ "$weight" -gt 10 ]; then
            echo -e "${RED}权重值 $weight 超出范围，请使用 1-10 之间的数值${NC}"
            return 1
        fi
    done

    return 0
}

# 预览端口组权重配置
preview_port_group_weight_config() {
    local port="$1"
    local rule_name="$2"
    local weight_input="$3"
    shift 3
    local targets=("$@")

    clear
    echo -e "${GREEN}=== 配置预览 ===${NC}"
    echo ""
    echo "规则组: $rule_name (端口: $port)"
    echo "权重配置变更:"

    # 获取当前权重（从第一个相关规则文件读取）
    local current_weights
    local first_rule_file=""
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                first_rule_file="$rule_file"
                if [ -n "$WEIGHTS" ]; then
                    if [[ "$WEIGHTS" == *","* ]]; then
                        # 完整权重字符串
                        IFS=',' read -ra current_weights <<< "$WEIGHTS"
                    else
                        # 单个权重值，需要查找完整权重
                        local found_full_weights=false
                        for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                            if [ -f "$check_rule_file" ]; then
                                if read_rule_file "$check_rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ] && [[ "$WEIGHTS" == *","* ]]; then
                                    IFS=',' read -ra current_weights <<< "$WEIGHTS"
                                    found_full_weights=true
                                    break
                                fi
                            fi
                        done

                        if [ "$found_full_weights" = false ]; then
                            # 默认相等权重
                            for ((i=0; i<${#targets[@]}; i++)); do
                                current_weights[i]=1
                            done
                        fi
                    fi
                else
                    # 默认相等权重
                    for ((i=0; i<${#targets[@]}; i++)); do
                        current_weights[i]=1
                    done
                fi
                break
            fi
        fi
    done

    # 解析新权重
    IFS=',' read -ra new_weights <<< "$weight_input"

    # 计算总权重
    local total_weight=0
    for weight in "${new_weights[@]}"; do
        total_weight=$((total_weight + weight))
    done

    # 显示变更详情
    for ((i=0; i<${#targets[@]}; i++)); do
        local old_weight="${current_weights[i]:-1}"
        local new_weight="${new_weights[i]}"
        local percentage
        if command -v bc >/dev/null 2>&1; then
            percentage=$(echo "scale=1; $new_weight * 100 / $total_weight" | bc 2>/dev/null || echo "0.0")
        else
            percentage=$(awk "BEGIN {printf \"%.1f\", $new_weight * 100 / $total_weight}")
        fi

        if [ "$old_weight" != "$new_weight" ]; then
            echo -e "  $((i+1)). ${targets[i]}: $old_weight → ${GREEN}$new_weight${NC} ${BLUE}($percentage%)${NC}"
        else
            echo -e "  $((i+1)). ${targets[i]}: $new_weight ${BLUE}($percentage%)${NC}"
        fi
    done

    echo ""
    read -p "确认应用此配置? [y/n]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 应用权重配置到该端口的所有相关规则
        apply_port_group_weight_config "$port" "$weight_input"
    else
        echo -e "${YELLOW}已取消配置更改${NC}"
        read -p "按回车键返回..."
    fi
}

# 应用端口组权重配置
apply_port_group_weight_config() {
    local port="$1"
    local weight_input="$2"

    local updated_count=0

    # 更新该端口的所有相关规则文件
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                # 更新规则文件中的权重配置
                # 对于第一个规则，存储完整权重；对于其他规则，存储对应的单个权重
                local rule_index=0
                local target_weight="$weight_input"

                # 计算当前规则在同端口规则中的索引
                for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                    if [ -f "$check_rule_file" ]; then
                        if read_rule_file "$check_rule_file" && [ "$RULE_ROLE" = "1" ] && [ "$LISTEN_PORT" = "$port" ]; then
                            if [ "$check_rule_file" = "$rule_file" ]; then
                                break
                            fi
                            rule_index=$((rule_index + 1))
                        fi
                    fi
                done

                # 根据规则索引确定要存储的权重
                if [ $rule_index -eq 0 ]; then
                    # 第一个规则存储完整权重
                    target_weight="$weight_input"
                else
                    # 其他规则存储对应位置的单个权重
                    IFS=',' read -ra weight_array <<< "$weight_input"
                    target_weight="${weight_array[$rule_index]:-1}"
                fi

                if grep -q "^WEIGHTS=" "$rule_file"; then
                    # 更新现有的WEIGHTS字段
                    if command -v sed >/dev/null 2>&1; then
                        sed -i.bak "s/^WEIGHTS=.*/WEIGHTS=\"$target_weight\"/" "$rule_file" && rm -f "$rule_file.bak"
                    else
                        # 如果没有sed，使用awk替代
                        awk -v new_weights="WEIGHTS=\"$target_weight\"" '
                            /^WEIGHTS=/ { print new_weights; next }
                            { print }
                        ' "$rule_file" > "$rule_file.tmp" && mv "$rule_file.tmp" "$rule_file"
                    fi
                else
                    # 如果没有WEIGHTS字段，在文件末尾添加
                    echo "WEIGHTS=\"$target_weight\"" >> "$rule_file"
                fi
                updated_count=$((updated_count + 1))
            fi
        fi
    done

    if [ $updated_count -gt 0 ]; then
        echo -e "${GREEN}✓ 已更新 $updated_count 个规则文件的权重配置${NC}"
        echo -e "${YELLOW}正在重启服务以应用更改...${NC}"

        # 重启realm服务
        if service_restart; then
            echo -e "${GREEN}✓ 服务重启成功，权重配置已生效${NC}"
        else
            echo -e "${RED}✗ 服务重启失败，请检查配置${NC}"
        fi
    else
        echo -e "${RED}✗ 未找到相关规则文件${NC}"
    fi

    read -p "按回车键返回..."
}

main "$@"
