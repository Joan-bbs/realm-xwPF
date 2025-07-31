#!/bin/bash

# 全局变量声明
ROLE=""
NAT_LISTEN_PORT=""
NAT_LISTEN_IP=""
NAT_THROUGH_IP="::"
REMOTE_IP=""
REMOTE_PORT=""
EXIT_LISTEN_PORT=""
FORWARD_IP=""
FORWARD_PORT=""
FORWARD_TARGET=""  #支持多地址和域名

# 配置变量
SECURITY_LEVEL=""  # 传输模式：standard, tls_self, tls_ca
TLS_CERT_PATH=""   # TLS证书路径
TLS_KEY_PATH=""    # TLS私钥路径
TLS_SERVER_NAME="" # TLS服务器名称(SNI)

RULE_ID=""
RULE_NAME=""

# 颜色定义
RED='\033[0;31m'      # 错误、危险、禁用状态
GREEN='\033[0;32m'    # 成功、正常、启用状态
YELLOW='\033[1;33m'   # 警告、特殊状态、重要提示
BLUE='\033[0;34m'     # 信息、标识、中性操作
WHITE='\033[1;37m'    # 关闭状态、默认文本
NC='\033[0m'          # 重置颜色

# 核心路径变量
REALM_PATH="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
MANAGER_CONF="${CONFIG_DIR}/manager.conf"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SYSTEMD_PATH="/etc/systemd/system/realm.service"
LOG_PATH="/var/log/realm.log"

# 转发配置管理路径
RULES_DIR="${CONFIG_DIR}/rules"

# 定时任务管理路径
CRON_DIR="${CONFIG_DIR}/cron"
CRON_TASKS_FILE="${CRON_DIR}/tasks.conf"

# 默认伪装域名（双端realm搭建隧道需要相同SNI）
DEFAULT_SNI_DOMAIN="www.tesla.com"

# 获取默认伪装域名（双端realm搭建隧道需要相同SNI）
get_random_mask_domain() {
    echo "$DEFAULT_SNI_DOMAIN"
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

# 安装依赖工具
install_dependencies() {
    local missing_tools=()
    local tools_to_check=("curl" "wget" "tar" "systemctl" "grep" "cut" "bc")

    echo -e "${YELLOW}正在检查必备依赖工具...${NC}"

    # 检查缺失的工具
    for tool in "${tools_to_check[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        else
            echo -e "${GREEN}✓${NC} $tool 已安装"
        fi
    done

    # 单独检查netcat-openbsd版本
    if ! check_netcat_openbsd; then
        missing_tools+=("nc")
        echo -e "${YELLOW}✗${NC} nc 需要安装netcat-openbsd版本"
    else
        echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 已安装"
    fi

    # 如果有缺失的工具，自动安装
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}需要安装以下工具: ${missing_tools[*]}${NC}"

        # 使用 apt-get 安装依赖
        echo -e "${BLUE}使用 apt-get 安装依赖,下载中...${NC}"
        apt-get update -qq >/dev/null 2>&1
        for tool in "${missing_tools[@]}"; do
            case "$tool" in
                "curl") apt-get install -y curl >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} curl 安装成功" ;;
                "wget") apt-get install -y wget >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} wget 安装成功" ;;
                "tar") apt-get install -y tar >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} tar 安装成功" ;;
                "systemctl") apt-get install -y systemd >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} systemd 安装成功" ;;
                "bc") apt-get install -y bc >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} bc 安装成功" ;;
                "nc")
                    # 确保安装正确的netcat版本
                    apt-get remove -y netcat-traditional >/dev/null 2>&1
                    apt-get install -y netcat-openbsd >/dev/null 2>&1 && echo -e "${GREEN}✓${NC} nc (netcat-openbsd) 安装成功"
                    ;;
            esac
        done
    else
        echo -e "${GREEN}所有必备工具已安装完成${NC}"
    fi
    echo ""
}

# 检查必备依赖工具
check_dependencies() {
    local missing_tools=()
    local tools_to_check=("curl" "wget" "tar" "systemctl" "grep" "cut" "bc")

    # 检查基础工具
    for tool in "${tools_to_check[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    # 单独检查netcat-openbsd
    if ! check_netcat_openbsd; then
        missing_tools+=("nc")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}错误: 缺少必备工具: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}请先选择菜单选项1进行安装，或手动运行安装命令:${NC}"
        echo -e "${BLUE}curl -fsSL https://raw.githubusercontent.com/zywe03/PortEasy/main/xwPF.sh | sudo bash -s install${NC}"
        exit 1
    fi
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
    ip=$(curl -s --connect-timeout 5 --max-time 10 $curl_opts https://ipinfo.io/ip 2>/dev/null | tr -d '\n\r ')
    if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]; then
        echo "$ip"
        return 0
    fi

    # 备用cloudflare trace
    ip=$(curl -s --connect-timeout 5 --max-time 10 $curl_opts https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip=" | cut -d'=' -f2 | tr -d '\n\r ')
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
SCRIPT_VERSION="v1.0.0"

# 中转服务器配置
NAT_LISTEN_PORT=$NAT_LISTEN_PORT
NAT_LISTEN_IP=$NAT_LISTEN_IP
NAT_THROUGH_IP=$NAT_THROUGH_IP
REMOTE_IP=$REMOTE_IP
REMOTE_PORT=$REMOTE_PORT

# 出口服务器配置
EXIT_LISTEN_PORT=$EXIT_LISTEN_PORT
FORWARD_TARGET=$FORWARD_TARGET

# 兼容性：保留旧格式（如果存在）
FORWARD_IP=$FORWARD_IP
FORWARD_PORT=$FORWARD_PORT

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

    # 兼容性处理：如果没有新格式，从旧格式转换
    if [ -z "$FORWARD_TARGET" ] && [ -n "$FORWARD_IP" ] && [ -n "$FORWARD_PORT" ]; then
        FORWARD_TARGET="$FORWARD_IP:$FORWARD_PORT"
    fi

    # 解析转发目标为IP和端口（用于向后兼容）
    if [ -n "$FORWARD_TARGET" ] && [ -z "$FORWARD_IP" ]; then
        # 提取第一个地址作为主要地址（向后兼容）
        local first_target=$(echo "$FORWARD_TARGET" | cut -d',' -f1)
        if [[ "$first_target" == *":"* ]]; then
            FORWARD_IP=$(echo "$first_target" | cut -d':' -f1)
            FORWARD_PORT=$(echo "$first_target" | cut -d':' -f2)
        fi
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
        # 直接检查输出中是否包含realm进程（更简单可靠）
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

# 检查防火墙
check_firewall() {
    local port="$1"
    local service_name="$2"

    if [ -z "$port" ]; then
        return 0
    fi

    echo -e "${YELLOW}检查防火墙状态...${NC}"

    # 检查ufw
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "${BLUE}检测到 UFW 防火墙已启用${NC}"
        read -p "是否自动放行端口 $port？(y/n): " allow_port
        if [[ "$allow_port" =~ ^[Yy]$ ]]; then
            ufw allow "$port" >/dev/null 2>&1
            echo -e "${GREEN}✓ UFW 已放行端口 $port${NC}"
        fi
    # 检查firewalld
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        echo -e "${BLUE}检测到 Firewalld 防火墙已启用${NC}"
        read -p "是否自动放行端口 $port？(y/n): " allow_port
        if [[ "$allow_port" =~ ^[Yy]$ ]]; then
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
            echo -e "${GREEN}✓ Firewalld 已放行端口 $port${NC}"
        fi
    # 检查iptables
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L INPUT 2>/dev/null | grep -q "DROP\|REJECT"; then
            echo -e "${BLUE}检测到 iptables 防火墙规则${NC}"
            read -p "是否自动放行端口 $port？(y/n): " allow_port
            if [[ "$allow_port" =~ ^[Yy]$ ]]; then
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
                echo -e "${GREEN}✓ iptables 已放行端口 $port${NC}"
                echo -e "${YELLOW}注意: 请手动保存 iptables 规则以确保重启后生效${NC}"
            fi
        fi
    else
        echo -e "${GREEN}✓ 未检测到活跃的防火墙${NC}"
    fi
}

# 测试IP或域名的连通性
check_connectivity() {
    local target="$1"
    local port="$2"
    local timeout=3

    # 检查参数
    if [ -z "$target" ] || [ -z "$port" ]; then
        return 1
    fi

    # 使用nc检测连通性（netcat-openbsd已确保安装）
    nc -z -w$timeout "$target" "$port" >/dev/null 2>&1
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

    # 域名格式检查（简化）
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

# 验证JSON配置文件语法
validate_json_config() {
    local config_file="$1"

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}配置文件不存在: $config_file${NC}"
        return 1
    fi

    # 使用python验证JSON语法（如果可用）
    if command -v python3 >/dev/null 2>&1; then
        if python3 -m json.tool "$config_file" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ JSON配置文件语法正确${NC}"
            return 0
        else
            echo -e "${RED}✗ JSON配置文件语法错误${NC}"
            echo -e "${YELLOW}使用以下命令查看详细错误:${NC}"
            echo -e "${GREEN}python3 -m json.tool $config_file${NC}"
            return 1
        fi
    elif command -v jq >/dev/null 2>&1; then
        if jq empty "$config_file" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ JSON配置文件语法正确${NC}"
            return 0
        else
            echo -e "${RED}✗ JSON配置文件语法错误${NC}"
            echo -e "${YELLOW}使用以下命令查看详细错误:${NC}"
            echo -e "${GREEN}jq empty $config_file${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠ 无法验证JSON语法（缺少python3或jq）${NC}"
        return 0
    fi
}

# 获取中转服务器监听IP（用户动态输入）
get_nat_server_listen_ip() {
    echo "${NAT_LISTEN_IP:-::}"
}

# 获取落地服务器监听IP（固定为双栈监听）
get_exit_server_listen_ip() {
    echo "::"
}

# 生成转发endpoints配置
generate_forward_endpoints_config() {
    local target="${FORWARD_TARGET:-$FORWARD_IP:$FORWARD_PORT}"
    local listen_ip=$(get_exit_server_listen_ip)

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

        echo "\"endpoints\": [
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${main_address}\"${extra_addresses}${transport_line}
        }
    ]"
    else
        # 单地址配置
        echo "\"endpoints\": [
        {
            \"listen\": \"${listen_ip}:${EXIT_LISTEN_PORT}\",
            \"remote\": \"${target}\"${transport_line}
        }
    ]"
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
        # 向后兼容：为旧规则文件设置默认备注
        RULE_NOTE="${RULE_NOTE:-}"
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

# 列出所有规则（用于管理操作）
list_rules_for_management() {
    if [ ! -d "$RULES_DIR" ] || [ -z "$(ls -A "$RULES_DIR"/*.conf 2>/dev/null)" ]; then
        echo -e "${BLUE}暂无转发规则${NC}"
        return 1
    fi

    # 中转服务器规则
    local has_relay_rules=false
    local relay_count=0
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_and_check_relay_rule "$rule_file"; then
                if [ "$has_relay_rules" = false ]; then
                    echo -e "${GREEN}中转服务器:${NC}"
                    has_relay_rules=true
                fi
                relay_count=$((relay_count + 1))

                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                local display_target=$(smart_display_target "$REMOTE_HOST")
                local rule_display_name="$RULE_NAME"
                if [ $relay_count -gt 1 ]; then
                    rule_display_name="$RULE_NAME-$relay_count"
                fi

                # 构建负载均衡信息
                local balance_mode="${BALANCE_MODE:-off}"
                local balance_info=$(get_balance_info_display "$REMOTE_HOST" "$balance_mode")

                local through_display="${THROUGH_IP:-::}"
                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info"
            fi
        fi
    done

    # 落地服务器规则
    local has_exit_rules=false
    local exit_count=0
    for rule_file in "${RULES_DIR}"/rule-*.conf; do
        if [ -f "$rule_file" ]; then
            if read_rule_file "$rule_file" && [ "$RULE_ROLE" = "2" ]; then
                if [ "$has_exit_rules" = false ]; then
                    if [ "$has_relay_rules" = true ]; then
                        echo ""
                    fi
                    echo -e "${GREEN}落地服务器 (双端Realm搭建隧道):${NC}"
                    has_exit_rules=true
                fi
                exit_count=$((exit_count + 1))

                local status_color="${GREEN}"
                local status_text="启用"
                if [ "$ENABLED" != "true" ]; then
                    status_color="${RED}"
                    status_text="禁用"
                fi

                # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                local target_host="${FORWARD_TARGET%:*}"
                local target_port="${FORWARD_TARGET##*:}"
                local display_target=$(smart_display_target "$target_host")
                local rule_display_name="$RULE_NAME"
                if [ $exit_count -gt 1 ]; then
                    rule_display_name="$RULE_NAME-$exit_count"
                fi

                # 落地服务器不需要负载均衡信息
                local balance_info=""

                echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$rule_display_name${NC} ($LISTEN_PORT → $display_target:$target_port) [${status_color}$status_text${NC}]$balance_info"
            fi
        fi
    done

    return 0
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

# 获取规则总数
get_rules_count() {
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
                local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                local note_display=""
                if [ -n "$RULE_NOTE" ]; then
                    note_display=" | 备注: $RULE_NOTE"
                fi
                echo -e "  通用配置: ${YELLOW}$security_display${NC}${note_display} | 状态: ${status_color}$status_text${NC}"
                # 根据规则角色显示不同的转发信息
                if [ "$RULE_ROLE" = "2" ]; then
                    # 落地服务器使用FORWARD_TARGET
                    local display_ip=$(get_exit_server_listen_ip)
                    echo -e "  监听: ${GREEN}${LISTEN_IP:-$display_ip}:$LISTEN_PORT${NC} → 转发: ${GREEN}$FORWARD_TARGET${NC}"
                else
                    # 中转服务器使用REMOTE_HOST:REMOTE_PORT，显示格式：中转: 监听IP:端口 → 出口IP → 目标IP:端口
                    local display_ip=$(get_nat_server_listen_ip)
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
    echo -e "${GREEN}[2]${NC} 落地服务器 (双端Realm搭建隧道)"
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
                echo -e "${GREEN}已选择: 落地服务器 (双端Realm搭建隧道)${NC}"
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
LISTEN_IP="$(get_nat_server_listen_ip)"
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
    local ids_array
    local valid_ids=()
    local invalid_ids=()

    # 解析逗号分隔的ID
    IFS=',' read -ra ids_array <<< "$rule_ids"

    # 验证所有ID的有效性并收集规则信息
    for id in "${ids_array[@]}"; do
        # 去除空格
        id=$(echo "$id" | tr -d ' ')
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

    # 检查是否有无效ID
    if [ ${#invalid_ids[@]} -gt 0 ]; then
        echo -e "${RED}错误: 以下规则ID无效或不存在: ${invalid_ids[*]}${NC}"
        return 1
    fi

    # 检查是否有有效ID
    if [ ${#valid_ids[@]} -eq 0 ]; then
        echo -e "${RED}错误: 没有找到有效的规则ID${NC}"
        return 1
    fi

    # 显示所有要删除的规则信息
    echo -e "${YELLOW}即将删除以下规则:${NC}"
    echo ""
    for id in "${valid_ids[@]}"; do
        local rule_file="${RULES_DIR}/rule-${id}.conf"
        if read_rule_file "$rule_file"; then
            echo -e "${BLUE}规则ID: ${GREEN}$RULE_ID${NC} | ${BLUE}规则名称: ${GREEN}$RULE_NAME${NC} | ${BLUE}监听端口: ${GREEN}$LISTEN_PORT${NC}"
        fi
    done
    echo ""

    # 批量确认删除
    read -p "确认删除以上 ${#valid_ids[@]} 个规则？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local deleted_count=0
        # 循环调用delete_rule，跳过单个确认
        for id in "${valid_ids[@]}"; do
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

# JSON配置转换为规则文件
import_json_to_rules() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        echo -e "${RED}配置文件不存在${NC}"
        return 1
    fi

    # 清理现有规则
    echo -e "${BLUE}正在清理现有规则...${NC}"
    if [ -d "$RULES_DIR" ]; then
        rm -f "${RULES_DIR}"/rule-*.conf 2>/dev/null
    fi

    # 初始化规则目录
    init_rules_dir

    # 提取endpoints信息（支持负载均衡）
    local temp_file=$(mktemp)

    # 使用Python提取完整的endpoints信息（增强）
    local python_cmd=""
    if command -v python3 >/dev/null 2>&1; then
        python_cmd="python3"
    elif command -v python >/dev/null 2>&1; then
        python_cmd="python"
    fi

    if [ -n "$python_cmd" ]; then
        $python_cmd -c "
import json
import sys
import re

try:
    with open('$json_file', 'r') as f:
        data = json.load(f)

    if 'endpoints' in data:
        for i, endpoint in enumerate(data['endpoints']):
            listen = endpoint.get('listen', '')
            remote = endpoint.get('remote', '')
            extra_remotes = endpoint.get('extra_remotes', [])
            balance = endpoint.get('balance', '')
            listen_transport = endpoint.get('listen_transport', '')
            remote_transport = endpoint.get('remote_transport', '')
            through = endpoint.get('through', '')

            if listen and remote:
                # 判断服务器角色
                role = '2' if listen_transport else '1'  # listen_transport存在=落地服务器

                # 处理监听IP（落地服务器强制改为::）
                if role == '2':
                    # 落地服务器：提取端口，IP改为::
                    port_match = re.search(r':(\d+)$', listen)
                    if port_match:
                        listen = '::' + ':' + port_match.group(1)

                # 构建完整的目标列表
                targets = [remote]
                if extra_remotes:
                    targets.extend(extra_remotes)

                target_list = ','.join(targets)

                # 解析权重信息
                weights_str = ''
                if balance:
                    # 提取权重：支持 roundrobin: 2,3,1 或 iphash: 1,2,3 格式
                    weight_match = re.search(r'(?:roundrobin|iphash):\s*([0-9,\s]+)', balance)
                    if weight_match:
                        weights_str = weight_match.group(1).replace(' ', '')

                # 如果没有权重信息，根据服务器数量生成默认权重
                if not weights_str:
                    weights_str = ','.join(['1'] * len(targets))

                # 输出格式：监听地址|远程地址|目标列表|负载均衡|角色|监听传输|远程传输|权重|出口地址
                # 输出格式：listen|remote|target_list|balance|role|listen_transport|remote_transport|weights|through
                print('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}'.format(
                    listen, remote, target_list, balance, role, listen_transport, remote_transport, weights_str, through))
except Exception as e:
    sys.exit(1)
" > "$temp_file"
    else
        # 回退到简化方法（增强）
        awk '
            BEGIN {
                in_endpoint = 0; transport_buffer = ""
                extra_count = 0; collecting_extra = 0
            }

            /"endpoints":/ { in_endpoints = 1 }
            /^\s*{/ && in_endpoints { in_endpoint = 1 }

            /"listen":/ && in_endpoint {
                gsub(/[",]/, "", $2);
                listen = $2
            }
            /"remote":/ && in_endpoint {
                gsub(/[",]/, "", $2);
                remote = $2
            }
            /"through":/ && in_endpoint {
                gsub(/[",]/, "", $2);
                through = $2
            }
            /"extra_remotes":/ && in_endpoint {
                has_extra = 1
                # 开始计算extra_remotes数量
                extra_count = 0
                collecting_extra = 1
            }

            # 计算extra_remotes中的服务器数量
            collecting_extra && /"[^"]*:[0-9]+"/ {
                # 匹配IP:端口格式，计算数量
                line_content = $0
                while (match(line_content, /"[^"]*:[0-9]+"/, matched)) {
                    extra_count++
                    line_content = substr(line_content, RSTART + RLENGTH)
                }
            }

            /^\s*\]/ && collecting_extra {
                collecting_extra = 0
            }
            /"balance":/ && in_endpoint {
                gsub(/[",]/, "", $2);
                balance = $2
            }

            # 处理多行传输配置
            /"listen_transport":/ && in_endpoint {
                transport_buffer = $0
                # 如果传输配置在同一行
                if (match($0, /"listen_transport":\s*"([^"]*)"/, arr)) {
                    listen_transport = arr[1]
                    role = "2"
                    transport_buffer = ""
                } else {
                    # 开始收集多行传输配置
                    gsub(/.*"listen_transport":\s*"/, "", transport_buffer)
                    collecting_listen_transport = 1
                }
            }

            /"remote_transport":/ && in_endpoint {
                transport_buffer = $0
                # 如果传输配置在同一行
                if (match($0, /"remote_transport":\s*"([^"]*)"/, arr)) {
                    remote_transport = arr[1]
                    transport_buffer = ""
                } else {
                    # 开始收集多行传输配置
                    gsub(/.*"remote_transport":\s*"/, "", transport_buffer)
                    collecting_remote_transport = 1
                }
            }

            # 收集多行传输配置
            collecting_listen_transport && !/"listen_transport":/ {
                transport_buffer = transport_buffer $0
                if (/"$/) {
                    gsub(/".*/, "", transport_buffer)
                    listen_transport = transport_buffer
                    role = "2"
                    collecting_listen_transport = 0
                    transport_buffer = ""
                }
            }

            collecting_remote_transport && !/"remote_transport":/ {
                transport_buffer = transport_buffer $0
                if (/"$/) {
                    gsub(/".*/, "", transport_buffer)
                    remote_transport = transport_buffer
                    collecting_remote_transport = 0
                    transport_buffer = ""
                }
            }

            /^\s*}/ && in_endpoint && listen && remote {
                if (!role) role = "1"  # 默认中转服务器

                # 落地服务器监听IP改为::
                if (role == "2") {
                    if (match(listen, /:([0-9]+)$/, port_arr)) {
                        listen = "::" ":" port_arr[1]
                    }
                }

                extra_info = ""
                if (has_extra) extra_info = "LB"

                # 解析权重信息
                weights_str = ""
                if (balance != "") {
                    # 提取权重：支持 "roundrobin: 2,3,1" 或 "iphash: 1,2,3" 格式
                    if (match(balance, /(roundrobin|iphash):\s*([0-9,\s]+)/, weight_match)) {
                        weights_str = weight_match[2]
                        gsub(/\s/, "", weights_str)  # 移除空格
                    }
                }

                # 如果没有权重信息，根据目标数量生成默认权重
                if (weights_str == "") {
                    # 计算实际目标数量：main + extra_remotes
                    target_count = 1 + extra_count  # main remote + extra_remotes数量

                    weights_str = "1"
                    for (i = 2; i <= target_count; i++) {
                        weights_str = weights_str ",1"
                    }
                }

                # 输出格式：监听地址|远程地址|扩展信息|负载均衡|角色|监听传输|远程传输|权重|出口地址
                print listen "|" remote "|" extra_info "|" balance "|" role "|" listen_transport "|" remote_transport "|" weights_str "|" through

                # 重置变量
                listen = ""; remote = ""; through = ""; has_extra = 0; balance = ""; role = ""
                listen_transport = ""; remote_transport = ""; extra_count = 0
                collecting_extra = 0; in_endpoint = 0
            }
        ' "$json_file" > "$temp_file"
    fi

    if [ ! -s "$temp_file" ]; then
        rm -f "$temp_file"
        echo -e "${RED}无法解析配置文件${NC}"
        return 1
    fi

    local rule_count=0
    local rule_id=1

    # 逐行处理endpoints（增强）
    while IFS='|' read -r listen_addr remote_addr target_list balance_config rule_role listen_transport remote_transport weights_str through_addr; do
        [ -z "$listen_addr" ] || [ -z "$remote_addr" ] && continue

        # 解析监听地址和端口
        local listen_port=$(echo "$listen_addr" | sed 's/.*://')
        if [ -z "$listen_port" ] || ! echo "$listen_port" | grep -qE "^[0-9]+$"; then
            continue
        fi

        # 提取监听IP
        local listen_ip=$(echo "$listen_addr" | sed 's/:[0-9]*$//')

        # 设置默认角色
        [ -z "$rule_role" ] && rule_role="1"

        # 解析负载均衡配置
        local balance_mode="off"
        if [ -n "$balance_config" ]; then
            if echo "$balance_config" | grep -q "roundrobin"; then
                balance_mode="roundrobin"
            elif echo "$balance_config" | grep -q "iphash"; then
                balance_mode="iphash"
            fi
        fi

        # 解析目标列表和权重
        IFS=',' read -ra targets <<< "$target_list"
        local weight_array=()

        # 解析权重字符串
        if [ -n "$weights_str" ]; then
            IFS=',' read -ra weight_array <<< "$weights_str"
        fi

        # 确保权重数组与目标数组长度一致
        while [ ${#weight_array[@]} -lt ${#targets[@]} ]; do
            weight_array+=("1")  # 补充默认权重
        done

        local target_index=0
        local has_multiple_targets=false
        if [ ${#targets[@]} -gt 1 ]; then
            has_multiple_targets=true
            echo -e "${BLUE}提示：检测到${#targets[@]}个服务器，权重配置：${weights_str}${NC}"

            # 方案2：将完整权重存储到第一个规则中
            local first_rule_weights="$weights_str"
        fi

        for target in "${targets[@]}"; do
            target=$(echo "$target" | xargs)  # 去除空格
            [ -z "$target" ] && continue

            # 解析远程地址和端口
            local remote_host=$(echo "$target" | sed 's/:[0-9]*$//')
            local remote_port=$(echo "$target" | sed 's/.*://')
            if [ -z "$remote_host" ] || [ -z "$remote_port" ] || ! echo "$remote_port" | grep -qE "^[0-9]+$"; then
                continue
            fi

            # 生成规则名称
            local rule_name="中转"
            if [ "$rule_role" = "2" ]; then
                rule_name="落地"
            fi

            # 获取当前目标的权重
            local current_weight="${weight_array[$target_index]:-1}"

            # 解析传输配置
            local security_level="standard"
            local tls_server_name=""
            local tls_cert_path=""
            local tls_key_path=""
            local ws_path="/ws"

            # 处理传输配置
            local transport_config=""
            if [ "$rule_role" = "2" ] && [ -n "$listen_transport" ]; then
                # 落地服务器：解析listen_transport
                transport_config="$listen_transport"
            elif [ "$rule_role" = "1" ] && [ -n "$remote_transport" ]; then
                # 中转服务器：解析remote_transport
                transport_config="$remote_transport"
            fi

            # 解析传输配置字段
            if [ -n "$transport_config" ]; then
                # 检测传输类型并映射到正确的安全级别字符串
                # 优先使用自签证书模式，因为导入配置通常没有证书文件路径
                if echo "$transport_config" | grep -q "ws" && echo "$transport_config" | grep -q "tls"; then
                    # WebSocket + TLS - 统一使用自签模式
                    security_level="ws_tls_self"
                elif echo "$transport_config" | grep -q "tls"; then
                    # 纯TLS - 统一使用自签模式
                    security_level="tls_self"
                else
                    security_level="standard"         # 默认传输
                fi

                # 提取SNI/servername
                if echo "$transport_config" | grep -q "sni="; then
                    tls_server_name=$(echo "$transport_config" | sed -n 's/.*sni=\([^;]*\).*/\1/p')
                elif echo "$transport_config" | grep -q "servername="; then
                    tls_server_name=$(echo "$transport_config" | sed -n 's/.*servername=\([^;]*\).*/\1/p')
                fi

                # 提取WebSocket路径
                if echo "$transport_config" | grep -q "path="; then
                    ws_path=$(echo "$transport_config" | sed -n 's/.*path=\([^;]*\).*/\1/p')
                fi

                # 提取证书路径（如果有）
                if echo "$transport_config" | grep -q "cert="; then
                    tls_cert_path=$(echo "$transport_config" | sed -n 's/.*cert=\([^;]*\).*/\1/p')
                fi
                if echo "$transport_config" | grep -q "key="; then
                    tls_key_path=$(echo "$transport_config" | sed -n 's/.*key=\([^;]*\).*/\1/p')
                fi
            fi

            # 创建规则文件
            local rule_file="${RULES_DIR}/rule-${rule_id}.conf"
            cat > "$rule_file" <<EOF
# Realm 转发规则配置文件 (导入)
# 规则ID: $rule_id
# 创建时间: $(get_gmt8_time '+%Y-%m-%d %H:%M:%S')

RULE_ID=$rule_id
RULE_NAME="$rule_name"
RULE_ROLE="$rule_role"
SECURITY_LEVEL="$security_level"
LISTEN_PORT="$listen_port"
LISTEN_IP="$listen_ip"
THROUGH_IP="${through_addr:-::}"
REMOTE_HOST="$remote_host"
REMOTE_PORT="$remote_port"
TLS_SERVER_NAME="$tls_server_name"
TLS_CERT_PATH="$tls_cert_path"
TLS_KEY_PATH="$tls_key_path"
WS_PATH="$ws_path"
RULE_NOTE=""
ENABLED="true"
CREATED_TIME="$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')"

# 负载均衡配置
BALANCE_MODE="$balance_mode"
TARGET_STATES=""
WEIGHTS="$([ "$target_index" -eq 0 ] && [ -n "$first_rule_weights" ] && echo "$first_rule_weights" || echo "$current_weight")"
EOF

            # 落地服务器需要添加FORWARD_TARGET字段
            if [ "$rule_role" = "2" ]; then
                echo "FORWARD_TARGET=\"$remote_host:$remote_port\"" >> "$rule_file"
            fi

            # 添加故障转移配置
            cat >> "$rule_file" <<EOF

# 故障转移配置
FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"
EOF

            if [ -f "$rule_file" ]; then
                rule_count=$((rule_count + 1))
                local role_text="中转"
                [ "$rule_role" = "2" ] && role_text="落地"
                local weight_info=""
                if [ "$has_multiple_targets" = true ]; then
                    weight_info=" (权重: $current_weight)"
                fi
                echo -e "${GREEN}✓${NC} 创建${role_text}规则 $rule_id: $listen_port → $remote_host:$remote_port$weight_info"
            else
                echo -e "${RED}✗${NC} 创建规则 $rule_id 失败"
            fi

            rule_id=$((rule_id + 1))
            target_index=$((target_index + 1))
        done
    done < "$temp_file"

    rm -f "$temp_file"

    if [ $rule_count -gt 0 ]; then
        echo -e "${GREEN}成功导入 $rule_count 个规则${NC}"
        return 0
    else
        echo -e "${RED}未能导入任何规则${NC}"
        return 1
    fi
}

# 导入配置文件
import_config_file() {
    echo -e "${YELLOW}=== 导入配置文件 ===${NC}"
    echo ""

    # 获取脚本工作目录（智能搜索）
    local script_dir=$(get_best_script_dir)

    # 扫描脚本工作目录下的.json文件
    echo -e "${BLUE}正在扫描配置文件...${NC}"
    local json_files=()
    while IFS= read -r -d '' file; do
        json_files+=("$file")
    done < <(find "$script_dir" -maxdepth 1 -name "*.json" -type f -print0 2>/dev/null)

    # 检查是否找到文件
    if [ ${#json_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}未在脚本工作目录下找到 .json 配置文件${NC}"
        echo -e "${BLUE}脚本工作目录: $script_dir${NC}"
        echo ""
        echo -e "${GREEN}请输入配置文件的完整路径:${NC}"
        read -p "文件路径: " user_file_path
        echo ""

        # 验证用户输入的文件路径
        if [ -z "$user_file_path" ]; then
            echo -e "${BLUE}已取消操作${NC}"
            read -p "按回车键返回..."
            return
        fi

        if [ ! -f "$user_file_path" ]; then
            echo -e "${RED}文件不存在: $user_file_path${NC}"
            read -p "按回车键返回..."
            return
        fi

        if [[ ! "$user_file_path" =~ \.json$ ]]; then
            echo -e "${RED}文件必须是 .json 格式${NC}"
            read -p "按回车键返回..."
            return
        fi

        # 使用用户输入的文件
        local selected_file="$user_file_path"
        local filename=$(basename "$selected_file")
        echo -e "${BLUE}选择的文件: $filename${NC}"
        echo ""
    else
        # 显示找到的文件
        echo -e "${GREEN}找到以下配置文件:${NC}"
        for i in "${!json_files[@]}"; do
            local filename=$(basename "${json_files[$i]}")
            echo -e "${GREEN}$((i+1)).${NC} $filename"
        done
        echo ""

        # 用户选择文件
        echo -e "${BLUE}请选择文件编号 [1-${#json_files[@]}] 或输入配置文件的完整路径(如/zywe/*.json):${NC}"
        read -p "选择: " file_choice
        echo ""

        local selected_file=""
        local filename=""

        # 检查是否是数字编号
        if echo "$file_choice" | grep -qE "^[0-9]+$"; then
            # 数字编号选择
            if [ "$file_choice" -lt 1 ] || [ "$file_choice" -gt ${#json_files[@]} ]; then
                echo -e "${RED}无效编号${NC}"
                read -p "按回车键返回..."
                return
            fi
            selected_file="${json_files[$((file_choice-1))]}"
            filename=$(basename "$selected_file")
        else
            # 文件路径输入
            if [ -z "$file_choice" ]; then
                echo -e "${BLUE}已取消操作${NC}"
                read -p "按回车键返回..."
                return
            fi

            if [ ! -f "$file_choice" ]; then
                echo -e "${RED}文件不存在: $file_choice${NC}"
                read -p "按回车键返回..."
                return
            fi

            if [[ ! "$file_choice" =~ \.json$ ]]; then
                echo -e "${RED}文件必须是 .json 格式${NC}"
                read -p "按回车键返回..."
                return
            fi

            selected_file="$file_choice"
            filename=$(basename "$selected_file")
        fi

        echo -e "${BLUE}选择的文件: $filename${NC}"
        echo ""
    fi

    # 快速格式检查
    echo -e "${YELLOW}正在检查配置文件格式...${NC}"
    if ! grep -q '"endpoints"' "$selected_file" || \
       ! grep -q '"listen"' "$selected_file" || \
       ! grep -q '"remote"' "$selected_file"; then
        echo -e "${RED}检查配置文件有误，建议使用脚本重新生成${NC}"
        echo ""
        read -p "按回车键返回..."
        return
    fi

    # JSON语法验证
    if ! validate_json_config "$selected_file" >/dev/null 2>&1; then
        echo -e "${RED}检查配置文件有误，建议使用脚本重新生成${NC}"
        echo ""
        read -p "按回车键返回..."
        return
    fi

    echo -e "${GREEN}✓ 配置文件格式检查通过${NC}"
    echo ""

    # 提取endpoints信息进行预览
    echo -e "${BLUE}正在分析配置内容...${NC}"
    local endpoints_info=""

    local python_cmd=""
    if command -v python3 >/dev/null 2>&1; then
        python_cmd="python3"
    elif command -v python >/dev/null 2>&1; then
        python_cmd="python"
    fi

    if [ -n "$python_cmd" ]; then
        endpoints_info=$($python_cmd -c "
import json
import sys

try:
    with open('$selected_file', 'r') as f:
        data = json.load(f)

    if 'endpoints' in data:
        for endpoint in data['endpoints']:
            listen = endpoint.get('listen', '')
            remote = endpoint.get('remote', '')
            extra_remotes = endpoint.get('extra_remotes', [])
            balance = endpoint.get('balance', '')

            if listen and remote:
                # 构建完整的目标列表
                targets = [remote]
                if extra_remotes:
                    targets.extend(extra_remotes)

                # 构建负载均衡信息
                balance_info = ''
                if balance:
                    import re
                    if 'roundrobin' in balance:
                        balance_info = ' [轮询]'
                        # 提取并显示权重信息
                        weight_match = re.search(r'roundrobin:\s*([0-9,\s]+)', balance)
                        if weight_match and extra_remotes:
                            weights = weight_match.group(1).replace(' ', '')
                            balance_info += '[权重: ' + weights + ']'
                        elif extra_remotes:
                            balance_info += '[默认权重]'
                    elif 'iphash' in balance:
                        balance_info = ' [IP哈希]'
                        # 提取并显示权重信息
                        weight_match = re.search(r'iphash:\s*([0-9,\s]+)', balance)
                        if weight_match and extra_remotes:
                            weights = weight_match.group(1).replace(' ', '')
                            balance_info += '[权重: ' + weights + ']'
                elif extra_remotes:
                    balance_info = ' [轮询][默认权重]'

                # 显示格式：先显示负载均衡信息，然后逐行显示每个服务器
                print('发现端点配置:' + balance_info)
                for i, target in enumerate(targets):
                    print('  {0} -> {1}'.format(listen, target))

                print('')  # 空行分隔
except Exception as e:
    sys.exit(1)
")
    else
        endpoints_info=$(grep -A 30 '"endpoints"' "$selected_file" | awk '
            /"listen":/ {
                gsub(/[",]/, "", $2);
                listen = $2
            }
            /"remote":/ {
                gsub(/[",]/, "", $2);
                remote = $2
            }
            /"through":/ {
                gsub(/[",]/, "", $2);
                through = $2
            }
            /"extra_remotes":/ {
                has_extra = 1
                # 尝试计算extra_remotes数量
                extra_count = 0
                getline
                while ($0 ~ /["\[]/ && $0 !~ /[\]]/) {
                    if ($0 ~ /"[^"]*"/) extra_count++
                    getline
                }
                if ($0 ~ /"[^"]*"/) extra_count++
            }
            /"balance":/ {
                gsub(/[",]/, "", $2);
                balance = $2
            }
            /^\s*}/ && listen && remote {
                # 构建负载均衡信息
                balance_info = ""
                if (balance ~ /roundrobin/) {
                    balance_info = " [轮询]"
                    if (balance ~ /:/) {
                        split(balance, parts, ":")
                        if (length(parts) > 1) {
                            gsub(/^\s+|\s+$/, "", parts[2])
                            balance_info = balance_info "[权重" parts[2] "]"
                        }
                    }
                } else if (balance ~ /iphash/) {
                    balance_info = " [IP哈希]"
                } else if (has_extra) {
                    balance_info = " [轮询]"
                }

                print "发现端点配置:" balance_info
                print "  " listen " -> " remote
                if (has_extra && extra_count > 0) {
                    for (i = 1; i <= extra_count; i++) {
                        print "  " listen " -> (备用服务器" i ")"
                    }
                }
                print ""
                listen = ""; remote = ""; has_extra = 0; balance = ""; extra_count = 0
            }
        ')
    fi

    if [ -z "$endpoints_info" ]; then
        echo -e "${RED}检查配置文件有误，建议使用脚本重新生成${NC}"
        echo ""
        read -p "按回车键返回..."
        return
    fi

    # 计算实际的端点数量（以"发现端点配置:"开头的行）
    local endpoint_count=$(echo "$endpoints_info" | grep -c "发现端点配置:")
    if [ "$endpoint_count" -eq 0 ]; then
        # 如果没有找到新格式，使用旧的计算方式
        endpoint_count=$(echo "$endpoints_info" | grep -c " -> ")
        echo -e "${GREEN}发现 $endpoint_count 个端点配置:${NC}"
        echo "$endpoints_info" | sed 's/^/  /'
    else
        echo -e "${GREEN}配置预览:${NC}"
        echo "$endpoints_info"
    fi
    echo ""

    # 显示当前规则数量
    local current_rules=0
    if [ -d "$RULES_DIR" ]; then
        current_rules=$(find "$RULES_DIR" -name "rule-*.conf" -type f 2>/dev/null | wc -l)
    fi

    echo -e "${YELLOW}当前规则数量: $current_rules${NC}"
    echo -e "${YELLOW}即将导入规则: $endpoint_count${NC}"
    echo ""
    echo -e "${RED}警告: 导入操作将覆盖所有现有配置！${NC}"
    echo ""

    # 确认导入
    read -p "确认导入配置文件？(y/n): " confirm
    if ! echo "$confirm" | grep -qE "^[Yy]$"; then
        echo -e "${BLUE}已取消导入操作${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 执行导入
    echo ""
    echo -e "${YELLOW}正在导入配置...${NC}"

    if import_json_to_rules "$selected_file"; then
        echo -e "${GREEN}✓ 配置导入成功${NC}"
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
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local rule_display_name="$RULE_NAME"
                            if [ $relay_count -gt 1 ]; then
                                rule_display_name="$RULE_NAME-$relay_count"
                            fi
                            local display_ip=$(get_nat_server_listen_ip)
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: $RULE_NOTE"
                            fi
                            echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

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
                                echo -e "${GREEN}落地服务器 (双端Realm搭建隧道):${NC}"
                                has_exit_rules=true
                            fi
                            exit_count=$((exit_count + 1))
                            # 显示详细的转发配置信息
                            local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                            # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                            local target_host="${FORWARD_TARGET%:*}"
                            local target_port="${FORWARD_TARGET##*:}"
                            local display_target=$(smart_display_target "$target_host")
                            local rule_display_name="$RULE_NAME"
                            if [ $exit_count -gt 1 ]; then
                                rule_display_name="$RULE_NAME-$exit_count"
                            fi
                            local display_ip=$(get_exit_server_listen_ip)
                            echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                            local note_display=""
                            if [ -n "$RULE_NOTE" ]; then
                                note_display=" | 备注: $RULE_NOTE"
                            fi
                            echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

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
        echo -e "${GREEN}1.${NC} 查看/导入配置文件"
        echo -e "${GREEN}2.${NC} 添加新配置"
        echo -e "${GREEN}3.${NC} 删除配置"
        echo -e "${GREEN}4.${NC} 启用/禁用中转规则"
        echo -e "${BLUE}5.${NC} 负载均衡管理"
        echo -e "${GREEN}6.${NC} 返回主菜单"
        echo ""

        read -p "请输入选择 [1-6]: " choice
        echo ""

        case $choice in
            1)
                # 查看/导入配置文件子菜单
                while true; do
                    clear
                    echo -e "${GREEN}=== 查看/导入配置文件 ===${NC}"
                    echo ""
                    echo "请选择操作:"
                    echo -e "${GREEN}1.${NC} 查看配置文件"
                    echo -e "${GREEN}2.${NC} 导入配置文件"
                    echo -e "${GREEN}3.${NC} 返回上级菜单"
                    echo ""
                    read -p "请输入选择 [1-3]: " sub_choice
                    echo ""

                    case $sub_choice in
                        1)
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
                            read -p "按回车键继续..."
                            ;;
                        2)
                            import_config_file
                            ;;
                        3)
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
                if list_rules_for_management; then
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
                if list_rules_for_management; then
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
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
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

        # 只显示中转服务器规则（因为只有中转服务器需要负载均衡）
        local has_relay_rules=false
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                if read_rule_file "$rule_file"; then

                    if [ "$RULE_ROLE" = "1" ]; then
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

                    # 构建负载均衡信息
                    local balance_mode="${BALANCE_MODE:-off}"
                    local balance_info=$(get_balance_info_display "$REMOTE_HOST" "$balance_mode")

                    # 检查是否属于负载均衡组（同端口有多个中转规则或单规则多地址）
                    local is_load_balance_group=false
                    local same_port_count=0
                    local total_targets=1

                    # 检查同端口的规则数量
                    for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                        if [ -f "$check_rule_file" ]; then
                            if grep -q "^RULE_ROLE=\"1\"" "$check_rule_file" && grep -q "^LISTEN_PORT=\"$LISTEN_PORT\"" "$check_rule_file"; then
                                same_port_count=$((same_port_count + 1))
                            fi
                        fi
                    done

                    # 检查当前规则是否有多个地址
                    if [[ "$REMOTE_HOST" == *","* ]]; then
                        IFS=',' read -ra host_array <<< "$REMOTE_HOST"
                        total_targets=${#host_array[@]}
                    fi

                    # 判断是否为负载均衡组：同端口多规则 或 单规则多地址
                    if [ $same_port_count -gt 1 ] || [ $total_targets -gt 1 ]; then
                        is_load_balance_group=true
                    fi

                    # 只有负载均衡组才显示权重信息
                    if [ "$is_load_balance_group" = true ] && [ "$balance_mode" != "off" ] && [ -n "$WEIGHTS" ]; then
                        # 计算当前规则在负载均衡组中的索引
                        local rule_index=0
                        local current_port="$LISTEN_PORT"
                        local current_remote="$REMOTE_HOST"

                        # 按规则ID顺序查找当前规则在同端口组中的位置
                        for check_file in "${RULES_DIR}"/rule-*.conf; do
                            if [ -f "$check_file" ]; then
                                if grep -q "^RULE_ROLE=\"1\"" "$check_file" && grep -q "^LISTEN_PORT=\"$current_port\"" "$check_file"; then
                                    local file_remote=$(grep "^REMOTE_HOST=" "$check_file" | cut -d'"' -f2)
                                    local file_id=$(grep "^RULE_ID=" "$check_file" | cut -d'=' -f2)

                                    if [ "$file_id" = "$RULE_ID" ]; then
                                        break
                                    fi
                                    rule_index=$((rule_index + 1))
                                fi
                            fi
                        done

                        # 解析权重信息，智能获取当前规则的权重
                        local current_weight=1
                        if [[ "$WEIGHTS" == *","* ]]; then
                            # 完整权重字符串，按索引提取
                            IFS=',' read -ra weight_array <<< "$WEIGHTS"
                            current_weight="${weight_array[$rule_index]:-1}"
                        else
                            # 单个权重值，直接使用
                            current_weight="${WEIGHTS:-1}"
                        fi

                        # 计算总权重（需要获取完整权重信息）
                        local total_weight=0
                        local full_weights=""

                        # 查找同端口负载均衡组的完整权重信息
                        local current_port="$LISTEN_PORT"
                        for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                            if [ -f "$check_rule_file" ]; then
                                if grep -q "^RULE_ROLE=\"1\"" "$check_rule_file" && grep -q "^LISTEN_PORT=\"$current_port\"" "$check_rule_file"; then
                                    local temp_weights=$(grep "^WEIGHTS=" "$check_rule_file" | cut -d'"' -f2)
                                    if [[ "$temp_weights" == *","* ]]; then
                                        full_weights="$temp_weights"
                                        break
                                    fi
                                fi
                            fi
                        done

                        # 使用完整权重计算总权重
                        if [ -n "$full_weights" ]; then
                            IFS=',' read -ra full_weight_array <<< "$full_weights"
                            for w in "${full_weight_array[@]}"; do
                                total_weight=$((total_weight + w))
                            done
                        else
                            # 回退：计算同端口所有规则的权重总和
                            for check_rule_file in "${RULES_DIR}"/rule-*.conf; do
                                if [ -f "$check_rule_file" ]; then
                                    if grep -q "^RULE_ROLE=\"1\"" "$check_rule_file" && grep -q "^LISTEN_PORT=\"$current_port\"" "$check_rule_file"; then
                                        local temp_weight=$(grep "^WEIGHTS=" "$check_rule_file" | cut -d'"' -f2)
                                        if [ -n "$temp_weight" ] && [[ "$temp_weight" != *","* ]]; then
                                            total_weight=$((total_weight + temp_weight))
                                        fi
                                    fi
                                fi
                            done

                            # 如果还是没有权重，使用当前权重
                            if [ $total_weight -eq 0 ]; then
                                total_weight=$current_weight
                            fi
                        fi

                        # 计算百分比
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
                        if [ "$balance_mode" != "off" ]; then
                            local failover_enabled="${FAILOVER_ENABLED:-false}"
                            if [ "$failover_enabled" = "true" ]; then
                                # 读取真实健康状态
                                local health_status_file="/etc/realm/health/health_status.conf"
                                local overall_status="healthy"

                                if [ -f "$health_status_file" ]; then
                                    # 检查所有目标的健康状态
                                    if [[ "$REMOTE_HOST" == *","* ]]; then
                                        IFS=',' read -ra host_list <<< "$REMOTE_HOST"
                                        local failed_count=0
                                        local total_count=${#host_list[@]}

                                        for host in "${host_list[@]}"; do
                                            host=$(echo "$host" | xargs)
                                            local health_key="${RULE_ID}|${host}"
                                            local node_status=$(grep "^${health_key}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3)
                                            if [ "$node_status" = "failed" ]; then
                                                failed_count=$((failed_count + 1))
                                            fi
                                        done

                                        if [ "$failed_count" -eq "$total_count" ]; then
                                            overall_status="failed"
                                        elif [ "$failed_count" -gt 0 ]; then
                                            overall_status="partial"
                                        fi
                                    else
                                        # 单个目标
                                        local health_key="${RULE_ID}|${REMOTE_HOST}"
                                        local node_status=$(grep "^${health_key}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3)
                                        if [ "$node_status" = "failed" ]; then
                                            overall_status="failed"
                                        fi
                                    fi
                                fi

                                # 根据状态显示不同颜色
                                case "$overall_status" in
                                    "healthy")
                                        failover_info=" ${GREEN}[健康]${NC}"
                                        ;;
                                    "partial")
                                        failover_info=" ${YELLOW}[部分故障]${NC}"
                                        ;;
                                    "failed")
                                        failover_info=" ${RED}[故障]${NC}"
                                        ;;
                                esac
                            fi
                        fi

                        local weight_info=" ${GREEN}[权重: $current_weight]${NC} ${BLUE}($percentage%)${NC}"
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$RULE_NAME${NC} ($LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info$weight_info$failover_info"
                    else
                        # 非负载均衡组，不显示权重信息
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  ID ${BLUE}$RULE_ID${NC}: ${GREEN}$RULE_NAME${NC} ($LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT) [${status_color}$status_text${NC}]$balance_info"
                    fi
                else
                    # 非负载均衡组的故障转移信息处理
                        # 构建故障转移状态信息（复用上面的逻辑）
                        local failover_info=""
                        if [ "$balance_mode" != "off" ]; then
                            local failover_enabled="${FAILOVER_ENABLED:-false}"
                            if [ "$failover_enabled" = "true" ]; then
                                # 读取真实健康状态
                                local health_status_file="/etc/realm/health/health_status.conf"
                                local overall_status="healthy"

                                if [ -f "$health_status_file" ]; then
                                    # 检查所有目标的健康状态
                                    if [[ "$REMOTE_HOST" == *","* ]]; then
                                        IFS=',' read -ra host_list <<< "$REMOTE_HOST"
                                        local failed_count=0
                                        local total_count=${#host_list[@]}

                                        for host in "${host_list[@]}"; do
                                            host=$(echo "$host" | xargs)
                                            local health_key="${RULE_ID}|${host}"
                                            local node_status=$(grep "^${health_key}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3)
                                            if [ "$node_status" = "failed" ]; then
                                                failed_count=$((failed_count + 1))
                                            fi
                                        done

                                        if [ "$failed_count" -eq "$total_count" ]; then
                                            overall_status="failed"
                                        elif [ "$failed_count" -gt 0 ]; then
                                            overall_status="partial"
                                        fi
                                    else
                                        # 单个目标
                                        local health_key="${RULE_ID}|${REMOTE_HOST}"
                                        local node_status=$(grep "^${health_key}|" "$health_status_file" 2>/dev/null | cut -d'|' -f3)
                                        if [ "$node_status" = "failed" ]; then
                                            overall_status="failed"
                                        fi
                                    fi
                                fi

                                # 根据状态显示不同颜色
                                case "$overall_status" in
                                    "healthy")
                                        failover_info=" ${GREEN}[健康]${NC}"
                                        ;;
                                    "partial")
                                        failover_info=" ${YELLOW}[部分故障]${NC}"
                                        ;;
                                    "failed")
                                        failover_info=" ${RED}[故障]${NC}"
                                        ;;
                                esac
                            fi
                        fi

                    fi
                fi
            fi
        done

        if [ "$has_relay_rules" = false ]; then
            echo -e "${YELLOW}暂无中转服务器规则${NC}"
            echo -e "${BLUE}提示: 只有中转服务器支持负载均衡功能${NC}"
            echo ""
            read -p "按回车键返回..."
            return
        fi

        echo ""
        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 切换负载均衡模式"
        echo -e "${BLUE}2.${NC} 权重配置管理"
        echo -e "${YELLOW}3.${NC} 开启/关闭故障转移"
        echo -e "${RED}4.${NC} 返回上级菜单"
        echo ""

        read -p "请输入选择 [1-4]: " choice
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
            4)
                # 返回上级菜单
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-4${NC}"
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
        declare -a rule_letters
        declare -a rule_ports
        declare -a rule_names
        declare -A letter_to_port

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

                # 生成字母A、B、C等
                local letter_index=${#rule_letters[@]}
                local letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                local letter=${letters:$letter_index:1}
                rule_letters+=("$letter")
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")
                letter_to_port[$letter]="$port_key"

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

                echo -e "${GREEN}$letter.${NC} ${port_configs[$port_key]} (端口: $port_key) $balance_display - $target_count个目标服务器"
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
        read -p "请输入要切换负载均衡模式的规则字母: " choice

        if [ -z "$choice" ]; then
            return
        fi

        choice=$(echo "$choice" | tr '[:lower:]' '[:upper:]')

        if [ -z "${letter_to_port[$choice]}" ]; then
            echo -e "${RED}无效的规则字母${NC}"
            read -p "按回车键继续..."
            continue
        fi

        local selected_port="${letter_to_port[$choice]}"
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
                    local display_ip=$(get_exit_server_listen_ip)
                else
                    local display_ip=$(get_nat_server_listen_ip)
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
    echo -e "${GREEN}[2]${NC} 落地服务器 (双端Realm搭建隧道)"
    echo ""

    while true; do
        read -p "请输入数字 [1-2]: " ROLE
        case $ROLE in
            1)
                echo -e "${GREEN}已选择: 中转服务器${NC}"
                break
                ;;
            2)
                echo -e "${GREEN}已选择: 落地服务器 (双端Realm搭建隧道)${NC}"
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

    # 检查防火墙
    check_firewall "$NAT_LISTEN_PORT" "中转服务器监听"

    # 如果端口被realm占用，跳过协议和传输配置
    if [ $port_status -eq 1 ]; then
        # 跳过协议和传输配置，直接进入规则创建
        echo -e "${BLUE}使用默认配置完成设置${NC}"
    else
    # 传输模式选择
    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[3]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[4]${NC} TLS+WebSocket (自签证书，伪装HTTPS流量)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (CA证书，伪装HTTPS流量)"
    echo ""

    while true; do
        read -p "请输入选择 [1-5]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME=$(get_random_mask_domain)
                    echo -e "${GREEN}已设置默认伪装域名: $TLS_SERVER_NAME${NC}"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            3)
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
            4)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME=$(get_random_mask_domain)
                    echo -e "${GREEN}已设置默认伪装域名: $TLS_SERVER_NAME${NC}"
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
            5)
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
                echo -e "${RED}无效选择，请输入 1-5${NC}"
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
    echo -e "${YELLOW}=== 落地服务器配置 (双端Realm搭建隧道) ===${NC}"
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

    # 检查防火墙
    check_firewall "$EXIT_LISTEN_PORT" "出口服务器监听"

    echo ""

    # 配置转发目标
    echo "配置转发目标 (就是设置好的本地业务软件,服务等等的信息):"
    echo ""
    echo -e "${YELLOW}双端realm搭建隧道${NC}"
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
    while true; do
        read -p "转发目标端口(业务端口): " FORWARD_PORT
        if validate_port "$FORWARD_PORT"; then
            echo -e "${GREEN}转发端口设置为: $FORWARD_PORT${NC}"
            break
        else
            echo -e "${RED}无效端口号，请输入 1-65535 之间的数字${NC}"
        fi
    done

    # 组合完整的转发目标（包含端口）
    FORWARD_TARGET="$FORWARD_TARGET:$FORWARD_PORT"

    # 测试转发目标连通性
    echo -e "${YELLOW}正在测试转发目标连通性...${NC}"
    local connectivity_ok=true

    # 解析并测试每个地址
    local addresses_part="${FORWARD_TARGET%:*}"
    IFS=',' read -ra TARGET_ADDRESSES <<< "$addresses_part"
    for addr in "${TARGET_ADDRESSES[@]}"; do
        addr=$(echo "$addr" | xargs)  # 去除空格
        echo -e "${BLUE}测试连接: $addr:$FORWARD_PORT${NC}"
        if check_connectivity "$addr" "$FORWARD_PORT"; then
            echo -e "${GREEN}✓ $addr:$FORWARD_PORT 连接成功${NC}"
        else
            echo -e "${RED}✗ $addr:$FORWARD_PORT 连接失败${NC}"
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

    # 设置兼容性变量（用于旧代码）
    FORWARD_IP=$(echo "${TARGET_ADDRESSES[0]}" | xargs)

    # 传输模式选择
    echo ""
    echo "请选择传输模式:"
    echo -e "${GREEN}[1]${NC} 默认传输 (不加密，理论最快)"
    echo -e "${GREEN}[2]${NC} TLS (自签证书，自动生成)"
    echo -e "${GREEN}[3]${NC} TLS (CA签发证书)"
    echo -e "${GREEN}[4]${NC} TLS+WebSocket (自签证书，伪装HTTPS流量)"
    echo -e "${GREEN}[5]${NC} TLS+WebSocket (CA证书，伪装HTTPS流量)"
    echo ""

    while true; do
        read -p "请输入选择 [1-5]: " transport_choice
        case $transport_choice in
            1)
                SECURITY_LEVEL="standard"
                echo -e "${GREEN}已选择: 默认传输${NC}"
                break
                ;;
            2)
                SECURITY_LEVEL="tls_self"
                echo -e "${GREEN}已选择: TLS自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME=$(get_random_mask_domain)
                    echo -e "${GREEN}已设置默认伪装域名: $TLS_SERVER_NAME${NC}"
                fi
                echo -e "${GREEN}TLS服务器名称设置为: $TLS_SERVER_NAME${NC}"
                break
                ;;
            3)
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
            4)
                SECURITY_LEVEL="ws_tls_self"
                echo -e "${GREEN}已选择: TLS+WebSocket自签证书${NC}"

                # TLS服务器名称配置
                echo ""
                read -p "请输入TLS服务器名称 (SNI) [默认www.tesla.com]: " TLS_SERVER_NAME
                if [ -z "$TLS_SERVER_NAME" ]; then
                    TLS_SERVER_NAME=$(get_random_mask_domain)
                    echo -e "${GREEN}已设置默认伪装域名: $TLS_SERVER_NAME${NC}"
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
            5)
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
                echo -e "${RED}无效选择，请输入 1-5${NC}"
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

# 获取最佳脚本工作目录
get_best_script_dir() {
    local locations=($(find_script_locations_enhanced))

    echo "${locations[0]}"
}

# 清理缓存函数
clear_script_location_cache() {
    rm -f "/tmp/xwPF_script_locations_cache"
    echo -e "${GREEN}✓ 脚本位置缓存已清理${NC}"
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
        # 复制到目标位置
        if cp "$realm_binary" "$REALM_PATH" && chmod +x "$REALM_PATH"; then
            echo -e "${GREEN}✓ realm 安装成功${NC}"

            # 验证安装并获取版本
            echo -e "${YELLOW}验证 realm 可执行性...${NC}"

            # 首先检查文件是否可执行
            if [ ! -x "${REALM_PATH}" ]; then
                echo -e "${RED}✗ realm 文件不可执行${NC}"
                rm -rf "$temp_dir"
                return 1
            fi

            # 尝试执行版本检查
            local version_output=""
            if version_output=$(${REALM_PATH} --version 2>&1); then
                echo -e "${GREEN}✓ ${version_output}${NC}"
            elif version_output=$(${REALM_PATH} -v 2>&1); then
                echo -e "${GREEN}✓ ${version_output}${NC}"
            else
                echo -e "${RED}✗ realm 无法执行版本检查${NC}"
                echo -e "${YELLOW}可能原因：${NC}"
                echo -e "${BLUE}  1. 架构不匹配（如在x86_64系统上使用aarch64版本）${NC}"
                echo -e "${BLUE}  2. 二进制文件损坏${NC}"
                echo -e "${BLUE}  3. 缺少依赖库${NC}"
                echo -e "${YELLOW}错误信息: ${version_output}${NC}"
                rm -rf "$temp_dir"
                return 1
            fi

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

# 多源下载策略
download_with_fallback() {
    local base_url="$1"
    local filename="$2"

    local sources=(
        ""  # 官方源
        "https://proxy.vvvv.ee/"
        "https://demo.52013120.xyz/"
        "https://ghfast.top/"
    )

    # 依次尝试各个源
    for proxy in "${sources[@]}"; do
        local full_url="${proxy}${base_url}"
        local source_name

        if [ -z "$proxy" ]; then
            source_name="GitHub官方源"
        else
            source_name="加速源: $(echo "$proxy" | sed 's|https://||' | sed 's|/$||')"
        fi

        echo -e "${BLUE}正在尝试 $source_name${NC}" >&2

        # 使用现有的reliable_download函数判断成功/失败
        local download_result
        if download_result=$(reliable_download "$full_url" "$filename"); then
            echo -e "${GREEN}✓ $source_name 下载成功${NC}" >&2
            echo "$download_result"  # 返回文件路径
            return 0
        else
            echo -e "${YELLOW}✗ $source_name 下载失败，尝试下一个源...${NC}" >&2
        fi
    done

    echo -e "${RED}✗ 所有下载源均失败${NC}" >&2
    return 1
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
        if curl -L --progress-bar --fail -o "$file_path" "$url"; then
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

            # 询问是否覆盖更新
            read -p "是否覆盖更新安装最新版本？(y/n) [默认: n]: " update_choice
            if [[ ! "$update_choice" =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}使用现有的 realm 安装${NC}"
                return 0
            fi
            echo -e "${YELLOW}将覆盖安装最新版本...${NC}"
        fi
    else
        echo -e "${YELLOW}未检测到 realm 安装，开始下载安装...${NC}"
    fi

    # 检测本地压缩包
    echo -e "${YELLOW}检测本地 realm 压缩包...${NC}"
    local script_dir=$(get_best_script_dir)
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

    # 获取最新版本号
    echo -e "${YELLOW}获取最新版本信息...${NC}"

    # 直接解析releases页面获取版本号
    LATEST_VERSION=$(curl -sL "https://github.com/zhboner/realm/releases" 2>/dev/null | \
        head -2100 | \
        sed -n 's|.*releases/tag/v\([0-9.]*\).*|v\1|p' | head -1)

    # 如果失败，使用硬编码版本号
    if [ -z "$LATEST_VERSION" ]; then
        echo -e "${YELLOW}使用当前最新版本 v2.7.0${NC}"
        LATEST_VERSION="v2.7.0"
    fi

    echo -e "${GREEN}✓ 检测到最新版本: ${LATEST_VERSION}${NC}"

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

    # 解压安装
    local work_dir=$(dirname "$download_file")
    local archive_name=$(basename "$download_file")

    if (cd "$work_dir" && tar -xzf "$archive_name" && cp realm ${REALM_PATH} && chmod +x ${REALM_PATH}); then
        echo -e "${GREEN}✓ realm 安装成功${NC}"
        rm -f "$download_file" "${work_dir}/realm"

        # 验证安装并获取真实版本
        echo -e "${YELLOW}验证 realm 可执行性...${NC}"

        # 首先检查文件是否可执行
        if [ ! -x "${REALM_PATH}" ]; then
            echo -e "${RED}✗ realm 文件不可执行${NC}"
            return 1
        fi

        # 尝试执行版本检查
        local version_output=""
        if version_output=$(${REALM_PATH} --version 2>&1); then
            echo -e "${GREEN}✓ ${version_output}${NC}"
            # 启动空服务完成安装
            start_empty_service
        elif version_output=$(${REALM_PATH} -v 2>&1); then
            echo -e "${GREEN}✓ ${version_output}${NC}"
            # 启动空服务完成安装
            start_empty_service
        else
            echo -e "${RED}✗ realm 无法执行版本检查${NC}"
            echo -e "${YELLOW}可能原因：${NC}"
            echo -e "${BLUE}  1. 下载的架构与系统不匹配${NC}"
            echo -e "${BLUE}  2. 二进制文件损坏${NC}"
            echo -e "${YELLOW}错误信息: ${version_output}${NC}"
            return 1
        fi
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
            \"listen\": \"${LISTEN_IP:-$(get_nat_server_listen_ip)}:${listen_port}\",
            \"remote\": \"${enabled_addresses[0]}:${remote_port}\"${extra_addresses}"
    else
        # 单地址配置
        endpoint_config="
        {
            \"listen\": \"${LISTEN_IP:-$(get_nat_server_listen_ip)}:${listen_port}\",
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

    # 第三阶段：全系统搜索（最后手段）
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
                        default_listen_ip=$(get_exit_server_listen_ip)
                    else
                        # 中转服务器使用动态输入的IP
                        default_listen_ip=$(get_nat_server_listen_ip)
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
                listen_ip=$(get_exit_server_listen_ip)
            else
                # 中转服务器使用动态输入的IP
                listen_ip=$(get_nat_server_listen_ip)
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

        endpoint_config="$endpoint_config
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

    # 如果没有规则，检查是否有传统配置
    if [ "$has_rules" = false ]; then
        if [ -f "$MANAGER_CONF" ]; then
            echo -e "${BLUE}未找到启用的规则，使用传统配置模式${NC}"
            generate_legacy_config
            return $?
        else
            echo -e "${BLUE}未找到启用的规则，生成空配置${NC}"
            # 生成空配置
            cat > "$CONFIG_PATH" <<EOF
{
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
    },
    "endpoints": []
}
EOF
            echo -e "${GREEN}✓ 空配置文件已生成${NC}"
            return 0
        fi
    fi

    # 生成基于规则的配置
    echo -e "${BLUE}找到 $enabled_count 个启用的规则，生成多规则配置${NC}"

    # 获取所有启用规则的endpoints
    local endpoints=$(generate_endpoints_from_rules)



    # 生成最终配置文件
    cat > "$CONFIG_PATH" <<EOF
{
    "log": {
        "level": "warn",
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
    },
    "endpoints": [$endpoints
    ]
}
EOF

    echo -e "${GREEN}✓ 多规则配置文件已生成${NC}"

    # 验证JSON语法
    if ! validate_json_config "$CONFIG_PATH"; then
        echo -e "${RED}✗ 配置文件生成失败，JSON语法错误${NC}"
        return 1
    fi

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
                    local display_ip=$(get_exit_server_listen_ip)
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                else
                    # 中转服务器使用REMOTE_HOST
                    local display_target=$(smart_display_target "$REMOTE_HOST")
                    local display_ip=$(get_nat_server_listen_ip)
                    local through_display="${THROUGH_IP:-::}"
                    echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                fi
            fi
        fi
    done
}

# 传统配置生成（向后兼容）
generate_legacy_config() {
    # 读取状态文件
    read_manager_conf

    if [ "$ROLE" -eq 1 ]; then
        # 中转服务器配置
        # 获取传输配置
        local transport_config=$(get_transport_config "$SECURITY_LEVEL" "$TLS_SERVER_NAME" "$TLS_CERT_PATH" "$TLS_KEY_PATH" "1" "$WS_PATH")
        local transport_line=""
        if [ -n "$transport_config" ]; then
            transport_line=",
            $transport_config"
        fi

        cat > "$CONFIG_PATH" <<EOF
{
    "log": {
        "level": "warn",
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
    },
    "endpoints": [
        {
            "listen": "${NAT_LISTEN_IP}:${NAT_LISTEN_PORT}",
            "remote": "${REMOTE_IP}:${REMOTE_PORT}"$([ -n "$NAT_THROUGH_IP" ] && [ "$NAT_THROUGH_IP" != "::" ] && echo ",
            \"through\": \"$NAT_THROUGH_IP\"" || echo "")${transport_line}
        }
    ]
}
EOF
        echo -e "${GREEN}✓ 中转服务器配置文件已生成${NC}"

        # 验证JSON语法
        if ! validate_json_config "$CONFIG_PATH"; then
            echo -e "${RED}✗ 配置文件生成失败，JSON语法错误${NC}"
            return 1
        fi

        echo -e "${BLUE}配置详情:${NC}"
        local display_ip=$(get_nat_server_listen_ip)
        echo -e "  监听地址: ${GREEN}${NAT_LISTEN_IP:-$display_ip}:$NAT_LISTEN_PORT${NC}"
        echo -e "  转发到: ${GREEN}$REMOTE_IP:$REMOTE_PORT${NC}"

    elif [ "$ROLE" -eq 2 ]; then
        # 出口服务器配置（双端Realm搭建隧道）
        local endpoints_config=$(generate_forward_endpoints_config)

        cat > "$CONFIG_PATH" <<EOF
{
    "log": {
        "level": "warn",
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
    },
    $endpoints_config
}
EOF
        echo -e "${GREEN}✓ 出口服务器配置文件已生成${NC}"

        # 验证JSON语法
        if ! validate_json_config "$CONFIG_PATH"; then
            echo -e "${RED}✗ 配置文件生成失败，JSON语法错误${NC}"
            return 1
        fi

        echo -e "${BLUE}配置详情:${NC}"
        echo -e "  监听端口: ${GREEN}$EXIT_LISTEN_PORT${NC}"
        echo -e "  转发到: ${GREEN}${FORWARD_TARGET:-$FORWARD_IP:$FORWARD_PORT}${NC}"

    else
        echo -e "${RED}错误: 无效的角色配置 (ROLE=${ROLE})${NC}"
        exit 1
    fi
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
        local base_script_url="https://raw.githubusercontent.com/zywe03/PortEasy/main/xwPF.sh"

        # 使用多源下载脚本
        local sources=(
            ""  # 官方源
            "https://proxy.vvvv.ee/"
            "https://demo.52013120.xyz/"
            "https://ghfast.top/"
        )

        local download_success=false
        for proxy in "${sources[@]}"; do
            local script_url="${proxy}${base_script_url}"
            local source_name

            if [ -z "$proxy" ]; then
                source_name="GitHub官方源"
            else
                source_name="加速源: $(echo "$proxy" | sed 's|https://||' | sed 's|/$||')"
            fi

            echo -e "${BLUE}尝试 $source_name${NC}"

            if curl -fsSL "$script_url" -o "${install_dir}/${script_name}" 2>/dev/null; then
                chmod +x "${install_dir}/${script_name}"
                echo -e "${GREEN}✓ $source_name 脚本更新成功${NC}"
                download_success=true
                break
            else
                echo -e "${YELLOW}✗ $source_name 下载失败，尝试下一个源...${NC}"
            fi
        done

        if [ "$download_success" = false ]; then
            echo -e "${RED}✗ 所有源脚本更新均失败${NC}"
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
        local base_script_url="https://raw.githubusercontent.com/zywe03/PortEasy/main/xwPF.sh"

        # 使用多源下载脚本
        local sources=(
            ""  # 官方源
            "https://proxy.vvvv.ee/"
            "https://demo.52013120.xyz/"
            "https://ghfast.top/"
        )

        local download_success=false
        for proxy in "${sources[@]}"; do
            local script_url="${proxy}${base_script_url}"
            local source_name

            if [ -z "$proxy" ]; then
                source_name="GitHub官方源"
            else
                source_name="加速源: $(echo "$proxy" | sed 's|https://||' | sed 's|/$||')"
            fi

            echo -e "${BLUE}尝试 $source_name${NC}"

            if curl -fsSL "$script_url" -o "${install_dir}/${script_name}" 2>/dev/null; then
                chmod +x "${install_dir}/${script_name}"
                echo -e "${GREEN}✓ $source_name 脚本下载成功${NC}"
                download_success=true
                break
            else
                echo -e "${YELLOW}✗ $source_name 下载失败，尝试下一个源...${NC}"
            fi
        done

        if [ "$download_success" = false ]; then
            echo -e "${RED}✗ 所有源脚本下载均失败${NC}"
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
    echo -e "${GREEN}=== xwPF Realm 一键脚本智能安装 v1.0.0 ===${NC}"
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
                        local display_ip=$(get_exit_server_listen_ip)
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                    else
                        # 中转服务器使用REMOTE_HOST
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local display_ip=$(get_nat_server_listen_ip)
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  ${GREEN}$RULE_NAME${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                    fi
                    # 构建安全级别显示
                    local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                    local note_display=""
                    if [ -n "$RULE_NOTE" ]; then
                        note_display=" | 备注: $RULE_NOTE"
                    fi
                    echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

                fi
            fi
        done
    else
        # 传统配置显示
        if [ "$ROLE" -eq 1 ]; then
            echo -e "配置模式: ${GREEN}传统模式 - 中转服务器${NC}"
            echo -e "监听端口: ${GREEN}$NAT_LISTEN_PORT${NC}"
            echo -e "转发到: ${GREEN}$REMOTE_IP:$REMOTE_PORT${NC}"
        elif [ "$ROLE" -eq 2 ]; then
            echo -e "配置模式: ${GREEN}传统模式 - 出口服务器 (双端Realm搭建隧道)${NC}"
            echo -e "监听端口: ${GREEN}$EXIT_LISTEN_PORT${NC}"

            # 显示转发目标（优先使用新格式）
            if [ -n "$FORWARD_TARGET" ]; then
                echo -e "转发到: ${GREEN}$FORWARD_TARGET${NC}"
                # 如果是多地址，显示详细信息
                if [[ "$FORWARD_TARGET" == *","* ]]; then
                    echo -e "转发模式: ${YELLOW}负载均衡 (多地址)${NC}"
                fi
            else
                echo -e "转发到: ${GREEN}$FORWARD_IP:$FORWARD_PORT${NC}"
            fi
        fi
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
                        local display_ip=$(get_exit_server_listen_ip)
                    else
                        local display_ip=$(get_nat_server_listen_ip)
                    fi
                    if $port_check_cmd 2>/dev/null | grep -q ":${LISTEN_PORT} "; then
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${GREEN}正在监听${NC}"
                    else
                        echo -e "端口 ${LISTEN_IP:-$display_ip}:$LISTEN_PORT ($RULE_NAME): ${RED}未监听${NC}"
                    fi
                fi
            fi
        done
    else
        # 传统模式：检查传统配置的端口
        if [ "$ROLE" -eq 1 ] && [ -n "$NAT_LISTEN_PORT" ]; then
            local display_ip=$(get_nat_server_listen_ip)
            if $port_check_cmd 2>/dev/null | grep -q ":${NAT_LISTEN_PORT} "; then
                echo -e "端口 ${NAT_LISTEN_IP:-$display_ip}:$NAT_LISTEN_PORT: ${GREEN}正在监听${NC}"
            else
                echo -e "端口 ${NAT_LISTEN_IP:-$display_ip}:$NAT_LISTEN_PORT: ${RED}未监听${NC}"
            fi
        elif [ "$ROLE" -eq 2 ] && [ -n "$EXIT_LISTEN_PORT" ]; then
            local exit_listen_ip=$(get_exit_server_listen_ip)
            if $port_check_cmd 2>/dev/null | grep -q ":${EXIT_LISTEN_PORT} "; then
                echo -e "端口 ${exit_listen_ip}:$EXIT_LISTEN_PORT: ${GREEN}正在监听${NC}"
            else
                echo -e "端口 ${exit_listen_ip}:$EXIT_LISTEN_PORT: ${RED}未监听${NC}"
            fi
        fi
    fi

    echo ""
    echo -e "${BLUE}详细状态信息:${NC}"
    systemctl status realm --no-pager -l
}

# 清理定时任务（卸载时调用）
cleanup_cron_tasks() {
    # 检查是否存在定时任务
    if [ ! -f "$CRON_TASKS_FILE" ] || [ ! -s "$CRON_TASKS_FILE" ]; then
        echo -e "${GRAY}  无定时任务需要清理${NC}"
        return 0
    fi

    # 显示将要清理的定时任务
    echo -e "${YELLOW}  发现以下定时任务:${NC}"
    local task_count=0
    while IFS='|' read -r id type interval next_time status created_time; do
        if [[ "$id" =~ ^[0-9]+$ ]]; then
            echo -e "    ID $id: $type"
            task_count=$((task_count + 1))
        fi
    done < "$CRON_TASKS_FILE"

    if [ "$task_count" -eq 0 ]; then
        echo -e "${GRAY}  无有效定时任务需要清理${NC}"
        return 0
    fi

    echo -e "${BLUE}  正在清理 $task_count 个定时任务...${NC}"

    # 清理每个定时任务
    while IFS='|' read -r id type interval next_time status created_time; do
        if [[ "$id" =~ ^[0-9]+$ ]]; then
            # 删除定时任务脚本
            local cron_script="/etc/realm/cron_restart_${id}.sh"
            if [ -f "$cron_script" ]; then
                rm -f "$cron_script" && echo -e "${GREEN}✓${NC}   已删除定时脚本: cron_restart_${id}.sh"
            fi

            # 从系统cron中删除相关条目
            if crontab -l 2>/dev/null | grep -q "cron_restart_${id}.sh"; then
                crontab -l 2>/dev/null | grep -v "# Realm restart task $id" | grep -v "cron_restart_${id}.sh" | crontab -
                echo -e "${GREEN}✓${NC}   已从crontab删除任务: $id"
            fi
        fi
    done < "$CRON_TASKS_FILE"

    # 删除定时任务配置文件
    if [ -f "$CRON_TASKS_FILE" ]; then
        rm -f "$CRON_TASKS_FILE" && echo -e "${GREEN}✓${NC}   已删除定时任务配置文件"
    fi

    # 删除定时任务目录（如果为空）
    if [ -d "$CRON_DIR" ]; then
        rmdir "$CRON_DIR" 2>/dev/null && echo -e "${GREEN}✓${NC}   已删除定时任务目录"
    fi

    # 删除定时任务日志
    if [ -f "/var/log/realm_cron.log" ]; then
        rm -f "/var/log/realm_cron.log" && echo -e "${GREEN}✓${NC}   已删除定时任务日志"
    fi

    echo -e "${GREEN}✓${NC} 定时任务清理完成"
}

# 清理防火墙规则（卸载时调用）
cleanup_firewall_rules() {
    echo -e "${BLUE}  正在检查防火墙规则...${NC}"

    # 收集realm配置的端口
    local ports_to_clean=()

    # 从管理配置文件读取端口
    if [ -f "$MANAGER_CONF" ]; then
        local nat_port=$(grep "^NAT_LISTEN_PORT=" "$MANAGER_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
        local exit_port=$(grep "^EXIT_LISTEN_PORT=" "$MANAGER_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
        [ -n "$nat_port" ] && [[ "$nat_port" =~ ^[0-9]+$ ]] && ports_to_clean+=("$nat_port")
        [ -n "$exit_port" ] && [[ "$exit_port" =~ ^[0-9]+$ ]] && ports_to_clean+=("$exit_port")
    fi

    # 从规则文件读取端口
    if [ -d "$RULES_DIR" ]; then
        for rule_file in "${RULES_DIR}"/rule-*.conf; do
            if [ -f "$rule_file" ]; then
                local listen_port=$(grep "^LISTEN_PORT=" "$rule_file" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
                [ -n "$listen_port" ] && [[ "$listen_port" =~ ^[0-9]+$ ]] && ports_to_clean+=("$listen_port")
            fi
        done
    fi

    # 去重端口列表
    local unique_ports=($(printf '%s\n' "${ports_to_clean[@]}" | sort -u))

    if [ ${#unique_ports[@]} -eq 0 ]; then
        echo -e "${GRAY}    无realm端口需要清理${NC}"
        return 0
    fi

    local total_cleaned=0

    # 安全清理UFW规则 - 只清理明确由realm添加的规则
    if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
        local ufw_cleaned=0
        for port in "${unique_ports[@]}"; do
            # 检查端口是否确实被realm使用（通过检查进程）
            if ! netstat -tlnp 2>/dev/null | grep ":$port " | grep -q "realm"; then
                # 只有当端口不再被realm使用时才清理防火墙规则
                if ufw status numbered 2>/dev/null | grep -q "ALLOW.*$port"; then
                    # 使用更安全的删除方式
                    echo "y" | ufw delete allow "$port" >/dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        ufw_cleaned=$((ufw_cleaned + 1))
                    fi
                fi
            fi
        done
        [ $ufw_cleaned -gt 0 ] && echo -e "${GREEN}✓${NC}   已清理UFW防火墙规则: ${ufw_cleaned}个端口"
        total_cleaned=$((total_cleaned + ufw_cleaned))
    fi

    # 安全清理Firewalld规则
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        local firewalld_cleaned=0
        for port in "${unique_ports[@]}"; do
            # 检查端口是否确实被realm使用
            if ! netstat -tlnp 2>/dev/null | grep ":$port " | grep -q "realm"; then
                # 检查并清理TCP规则
                if firewall-cmd --list-ports 2>/dev/null | grep -q "${port}/tcp"; then
                    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1
                    [ $? -eq 0 ] && firewalld_cleaned=$((firewalld_cleaned + 1))
                fi
                # 检查并清理UDP规则
                if firewall-cmd --list-ports 2>/dev/null | grep -q "${port}/udp"; then
                    firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1
                    [ $? -eq 0 ] && firewalld_cleaned=$((firewalld_cleaned + 1))
                fi
            fi
        done
        if [ $firewalld_cleaned -gt 0 ]; then
            firewall-cmd --reload >/dev/null 2>&1
            echo -e "${GREEN}✓${NC}   已清理Firewalld防火墙规则: ${firewalld_cleaned}个端口"
            total_cleaned=$((total_cleaned + firewalld_cleaned))
        fi
    fi

    # 对于iptables，由于规则复杂且风险高，不进行自动清理
    # 只在确实有端口且其他防火墙有清理时才显示信息
    if command -v iptables >/dev/null 2>&1 && [ $total_cleaned -gt 0 ]; then
        echo -e "${YELLOW}!${NC}   iptables规则需要手动检查清理"
    fi

    if [ $total_cleaned -gt 0 ]; then
        echo -e "${GREEN}✓${NC} 防火墙规则清理完成"
    else
        echo -e "${GRAY}    无需清理防火墙规则${NC}"
    fi
}

# 卸载 Realm 服务和配置
uninstall_realm() {
    echo -e "${RED}⚠️  警告: 即将分阶段卸载 Realm 端口转发服务${NC}"
    echo ""

    # 第一阶段：Realm 相关文件
    echo -e "${YELLOW}=== 第一阶段：Realm 服务和配置文件 ===${NC}"
    echo -e "${BLUE}此操作将删除以下 Realm 相关内容:${NC}"
    echo -e "  - Realm 主程序: $REALM_PATH"
    echo -e "  - 配置目录: $CONFIG_DIR"
    echo -e "  - 规则目录: $RULES_DIR"
    echo -e "  - 定时任务目录: $CRON_DIR"
    echo -e "  - 状态文件: $MANAGER_CONF"
    echo -e "  - 系统服务: $SYSTEMD_PATH"
    echo -e "  - 日志文件: $LOG_PATH"
    echo -e "  - 定时任务和相关脚本"
    echo -e "  - 防火墙规则和端口配置"
    echo -e "  - 临时文件和缓存"
    echo ""

    read -p "确认删除 Realm 服务和配置？(y/n): " confirm_realm
    if [[ ! "$confirm_realm" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}第一阶段卸载已取消${NC}"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}正在执行第一阶段卸载...${NC}"

    # 停止并禁用服务
    if systemctl is-active realm >/dev/null 2>&1; then
        echo -e "${BLUE}停止 Realm 服务...${NC}"
        systemctl stop realm
    fi

    if systemctl is-enabled realm >/dev/null 2>&1; then
        echo -e "${BLUE}禁用 Realm 服务...${NC}"
        systemctl disable realm >/dev/null 2>&1
    fi

    # 清理定时任务
    echo -e "${BLUE}清理定时任务...${NC}"
    cleanup_cron_tasks

    # 清理健康检查服务
    echo -e "${BLUE}清理健康检查服务...${NC}"
    stop_health_check_service
    rm -rf "/etc/realm/health" 2>/dev/null
    rm -f "/var/log/realm-health.log" 2>/dev/null

    # 清理锁文件和垃圾文件
    echo -e "${BLUE}清理锁文件和垃圾文件...${NC}"
    # 精确匹配我们的锁文件模式，避免误删
    for lock_pattern in "/var/lock/realm-health-check.lock" "/var/run/realm.pid" "/tmp/realm-*.tmp"; do
        for lock_file in $lock_pattern; do
            if [ -f "$lock_file" ]; then
                rm -f "$lock_file" && echo -e "${GREEN}✓${NC} 已删除: $lock_file"
            fi
        done
    done

    # 清理配置备份文件
    for backup_dir in "/etc/realm" "$RULES_DIR" "$CRON_DIR"; do
        if [ -d "$backup_dir" ]; then
            find "$backup_dir" -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.tmp" 2>/dev/null | while read -r file; do
                if [ -f "$file" ]; then
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除备份文件: $file"
                fi
            done &
        fi
    done
    wait

    # 清理防火墙规则
    echo -e "${BLUE}清理防火墙规则...${NC}"
    cleanup_firewall_rules

    # 全面强化删除 Realm 相关文件（确保删除所有可能的安装）
    echo -e "${BLUE}全面搜索并删除 Realm 文件和配置...${NC}"

    # 首先终止所有realm相关进程
    echo -e "${BLUE}终止 realm 相关进程...${NC}"
    local realm_processes=("realm" "realm2")
    for process in "${realm_processes[@]}"; do
        if pgrep "$process" >/dev/null 2>&1; then
            echo -e "${YELLOW}发现运行中的 $process 进程${NC}"
            pkill -f "$process" && echo -e "${GREEN}✓${NC} 已终止 $process 进程"
            sleep 2
            # 强制终止仍在运行的进程
            if pgrep "$process" >/dev/null 2>&1; then
                pkill -9 -f "$process" && echo -e "${GREEN}✓${NC} 已强制终止 $process 进程"
            fi
        fi
    done

    # 扩展搜索目录（包括所有可能的安装位置）
    local search_dirs=("/usr/local/bin" "/usr/bin" "/bin" "/sbin" "/usr/sbin" "/opt" "/tmp" "/root" "/home" "/var" "/usr/local" "/usr/share")

    # 并行搜索并删除 realm 主程序文件（全面搜索，包括realm2等变体）
    echo -e "${BLUE}全面搜索 realm 主程序文件...${NC}"
    local realm_patterns=("realm" "realm2" "*realm*")
    for dir in "${search_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # 搜索所有可能的realm文件变体
            for pattern in "${realm_patterns[@]}"; do
                find "$dir" -name "$pattern" -type f 2>/dev/null | while read -r file; do
                    if [ -f "$file" ] && [[ "$(basename "$file")" == *"realm"* ]]; then
                        echo -e "${YELLOW}发现 realm 文件: $file${NC}"
                        rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除: $file"
                    fi
                done &
            done
        fi
    done
    wait  # 等待所有并行搜索完成

    # 全面搜索并删除realm配置目录（包括realm2等变体）
    echo -e "${BLUE}搜索 realm 配置目录...${NC}"
    local config_dirs=("/etc" "/usr/local/etc" "/opt" "/root" "/home")
    local config_patterns=("realm" "realm2" "*realm*")
    for dir in "${config_dirs[@]}"; do
        if [ -d "$dir" ]; then
            for pattern in "${config_patterns[@]}"; do
                find "$dir" -name "$pattern" -type d 2>/dev/null | while read -r config_dir; do
                    if [ -d "$config_dir" ] && [[ "$(basename "$config_dir")" == *"realm"* ]]; then
                        echo -e "${YELLOW}发现 realm 配置目录: $config_dir${NC}"
                        rm -rf "$config_dir" && echo -e "${GREEN}✓${NC} 已删除配置目录: $config_dir"
                    fi
                done &
            done
        fi
    done
    wait

    # 全面搜索并删除realm系统服务文件（包括realm2等变体）
    echo -e "${BLUE}搜索 realm 系统服务文件...${NC}"
    local service_dirs=("/etc/systemd/system" "/lib/systemd/system" "/usr/lib/systemd/system")
    local service_patterns=("*realm*" "*realm2*")
    for dir in "${service_dirs[@]}"; do
        if [ -d "$dir" ]; then
            for pattern in "${service_patterns[@]}"; do
                find "$dir" -name "$pattern" -type f 2>/dev/null | while read -r service_file; do
                    if [ -f "$service_file" ] && [[ "$(basename "$service_file")" == *"realm"* ]]; then
                        echo -e "${YELLOW}发现 realm 服务文件: $service_file${NC}"
                        rm -f "$service_file" && echo -e "${GREEN}✓${NC} 已删除服务文件: $service_file"
                    fi
                done &
            done
        fi
    done
    wait

    # 全面搜索并删除realm相关日志文件
    echo -e "${BLUE}全面搜索 realm 日志文件...${NC}"
    local log_dirs=("/var/log" "/tmp" "/root" "/home" "/usr/local/var/log" "/opt")
    for log_dir in "${log_dirs[@]}"; do
        if [ -d "$log_dir" ]; then
            find "$log_dir" -name "*realm*" -type f 2>/dev/null | while read -r file; do
                if [ -f "$file" ]; then
                    echo -e "${YELLOW}发现 realm 日志文件: $file${NC}"
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除日志文件: $file"
                fi
            done &
        fi
    done
    wait  # 等待所有并行搜索完成

    # 全面清理临时文件、缓存和下载文件
    echo -e "${BLUE}全面清理临时文件和缓存...${NC}"

    # 清理新的脚本位置缓存
    rm -f "/tmp/xwPF_script_locations_cache" && echo -e "${GREEN}✓${NC} 已清理脚本位置缓存"
    rm -f "/tmp/xwPF_script_path_cache" && echo -e "${GREEN}✓${NC} 已清理脚本路径缓存"
    rm -f "/tmp/realm_path_cache" && echo -e "${GREEN}✓${NC} 已清理故障转移路径缓存"
    local tmp_dirs=("/tmp" "/var/tmp" "/root" "/home" "/usr/local/tmp")
    for tmp_dir in "${tmp_dirs[@]}"; do
        if [ -d "$tmp_dir" ]; then
            # 搜索realm相关文件
            find "$tmp_dir" -name "*realm*" -type f 2>/dev/null | while read -r file; do
                if [ -f "$file" ]; then
                    echo -e "${YELLOW}发现 realm 临时文件: $file${NC}"
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除临时文件: $file"
                fi
            done &

            # 搜索可能的realm下载文件
            find "$tmp_dir" -name "*.tar.gz" -type f 2>/dev/null | while read -r file; do
                if [ -f "$file" ] && tar -tzf "$file" 2>/dev/null | grep -q "realm"; then
                    echo -e "${YELLOW}发现 realm 下载文件: $file${NC}"
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除下载文件: $file"
                fi
            done &

            # 搜索规则文件备份和临时文件
            find "$tmp_dir" -name "rule-*.conf.bak" -o -name "rule-*.conf.tmp" -o -name "*.bak" -o -name "*.tmp" 2>/dev/null | while read -r file; do
                if [ -f "$file" ] && [[ "$(basename "$file")" == *"realm"* || "$(basename "$file")" == *"rule-"* ]]; then
                    echo -e "${YELLOW}发现 realm 备份文件: $file${NC}"
                    rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除备份文件: $file"
                fi
            done &
        fi
    done
    wait  # 等待所有并行搜索完成

    # 刷新systemd
    echo -e "${BLUE}刷新系统服务...${NC}"
    systemctl daemon-reload

    echo ""
    echo -e "${GREEN}✓ 第一阶段卸载完成！Realm 服务和所有相关文件已删除${NC}"
    echo ""

    # 第二阶段：脚本文件
    echo -e "${YELLOW}=== 第二阶段：xwPF 脚本文件 ===${NC}"
    echo -e "${BLUE}此操作将查找并删除所有 xwPF 相关文件${NC}"
    echo ""

    read -p "确认删除脚本文件？(y/n): " confirm_script
    if [[ "$confirm_script" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${YELLOW}正在查找并删除 xwPF 相关文件...${NC}"

        # 全局搜索 xwPF.sh 文件（多线程精确搜索）
        echo -e "${BLUE}全局搜索 xwPF.sh 文件...${NC}"

        # 全局搜索所有挂载点，xwPF.sh文件名唯一不会误删
        local search_roots=("/" "/usr" "/opt" "/home" "/root" "/var" "/tmp" "/etc")
        for root in "${search_roots[@]}"; do
            if [ -d "$root" ]; then
                find "$root" -name "xwPF.sh" -type f 2>/dev/null | while read -r file; do
                    if [ -f "$file" ]; then
                        rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除: $file"
                    fi
                done &
            fi
        done
        wait  # 等待所有并行搜索完成

        # 搜索 pf 命令（严格验证是否为 xwPF 相关）
        echo -e "${BLUE}搜索 pf 命令...${NC}"
        # 只在可执行文件目录搜索，避免误删其他pf命令
        local exec_dirs=("/usr/local/bin" "/usr/bin" "/bin" "/opt/bin" "/root/bin")
        for dir in "${exec_dirs[@]}"; do
            if [ -d "$dir" ]; then
                find "$dir" -name "pf" -type f 2>/dev/null | while read -r file; do
                    # 严格验证：必须包含xwPF特征字符串
                    if [ -f "$file" ] && grep -q "xwPF.*端口转发管理脚本\|xwPF.sh" "$file" 2>/dev/null; then
                        rm -f "$file" && echo -e "${GREEN}✓${NC} 已删除: $file"
                    fi
                done &
            fi
        done
        wait  # 等待所有并行搜索完成

        # 查找并删除指向 xwPF 的符号链接
        echo -e "${BLUE}搜索相关符号链接...${NC}"
        # 只在可执行文件目录搜索符号链接
        for dir in "${exec_dirs[@]}"; do
            if [ -d "$dir" ]; then
                find "$dir" -name "pf" -type l 2>/dev/null | while read -r link; do
                    target=$(readlink "$link" 2>/dev/null)
                    if [[ "$target" == *"xwPF"* ]]; then
                        rm -f "$link" && echo -e "${GREEN}✓${NC} 已删除符号链接: $link"
                    fi
                done &
            fi
        done
        wait  # 等待所有并行搜索完成

        echo ""
        echo -e "${GREEN}🗑️  完全卸载完成！${NC}"
        echo -e "${BLUE}所有 Realm 和 xwPF 相关文件已从系统中完全移除${NC}"
    else
        echo -e "${BLUE}脚本文件保留，可继续使用 pf 命令管理其他 Realm 服务${NC}"
    fi
    echo ""
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

    # 验证配置文件
    echo -e "${BLUE}配置文件验证:${NC}"
    if validate_json_config "$CONFIG_PATH"; then
        echo ""
    else
        echo -e "${RED}配置文件存在语法错误${NC}"
        echo ""
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
                            local display_ip=$(get_exit_server_listen_ip)
                            echo -e "    监听: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        else
                            # 中转服务器使用REMOTE_HOST
                            local display_target=$(smart_display_target "$REMOTE_HOST")
                            local display_ip=$(get_nat_server_listen_ip)
                            local through_display="${THROUGH_IP:-::}"
                            echo -e "    中转: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        fi
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: $RULE_NOTE"
                        fi
                        echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

                        if [ "$SECURITY_LEVEL" = "tls_self" ]; then
                            local display_sni="${TLS_SERVER_NAME:-$DEFAULT_SNI_DOMAIN}"
                            echo -e "    TLS自签证书 (SNI: $display_sni)"
                        elif [ "$SECURITY_LEVEL" = "tls_ca" ]; then
                            echo -e "    TLS CA证书 (域名: $TLS_SERVER_NAME)"
                            echo -e "    证书文件: $TLS_CERT_PATH"
                        fi
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
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                        local display_target=$(smart_display_target "$REMOTE_HOST")
                        local rule_display_name="$RULE_NAME"
                        if [ $relay_count -gt 1 ]; then
                            rule_display_name="$RULE_NAME-$relay_count"
                        fi
                        local display_ip=$(get_nat_server_listen_ip)
                        local through_display="${THROUGH_IP:-::}"
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $through_display → $display_target:$REMOTE_PORT"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: $RULE_NOTE"
                        fi
                        echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

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
                            echo -e "${GREEN}落地服务器 (双端Realm搭建隧道):${NC}"
                            has_exit_rules=true
                        fi
                        exit_count=$((exit_count + 1))
                        # 显示详细的转发配置信息
                        local security_display=$(get_security_display "$SECURITY_LEVEL" "$WS_PATH")
                        # 落地服务器使用FORWARD_TARGET而不是REMOTE_HOST
                        local target_host="${FORWARD_TARGET%:*}"
                        local target_port="${FORWARD_TARGET##*:}"
                        local display_target=$(smart_display_target "$target_host")
                        local rule_display_name="$RULE_NAME"
                        if [ $exit_count -gt 1 ]; then
                            rule_display_name="$RULE_NAME-$exit_count"
                        fi
                        local display_ip=$(get_exit_server_listen_ip)
                        echo -e "  • ${GREEN}$rule_display_name${NC}: ${LISTEN_IP:-$display_ip}:$LISTEN_PORT → $display_target:$target_port"
                        local note_display=""
                        if [ -n "$RULE_NOTE" ]; then
                            note_display=" | 备注: $RULE_NOTE"
                        fi
                        echo -e "    安全: ${YELLOW}$security_display${NC}${note_display}"

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
        # 检查是否有传统配置
        if [ -f "$MANAGER_CONF" ]; then
            # 有状态文件，显示传统模式
            source "$MANAGER_CONF" 2>/dev/null
            if [ "$ROLE" -eq 1 ]; then
                echo -e "配置模式: ${GREEN}传统模式${NC} - 中转服务器"
                local display_ip=$(get_nat_server_listen_ip)
                local through_display="${NAT_THROUGH_IP:-::}"
                echo -e "中转: ${YELLOW}${NAT_LISTEN_IP:-$display_ip}:$NAT_LISTEN_PORT${NC} → ${YELLOW}$through_display${NC} → ${GREEN}$REMOTE_IP:$REMOTE_PORT${NC}"
                if [ -n "$SECURITY_LEVEL" ]; then
                    local security_display=$(get_security_display "${SECURITY_LEVEL:-0}" "")
                    echo -e "通用配置: ${YELLOW}$security_display${NC}"
                fi
            elif [ "$ROLE" -eq 2 ]; then
                echo -e "配置模式: ${GREEN}传统模式${NC} - 出口服务器 (双端Realm搭建隧道)"
                local exit_listen_ip=$(get_exit_server_listen_ip)
                echo -e "监听端口: ${YELLOW}${exit_listen_ip}:$EXIT_LISTEN_PORT${NC}"
                if [ -n "$SECURITY_LEVEL" ]; then
                    local security_display=$(get_security_display "${SECURITY_LEVEL:-0}" "")
                    echo -e "通用配置: ${YELLOW}$security_display${NC}"
                fi
            fi
        else
            # 没有状态文件，显示简化提示
            echo -e "转发规则: ${YELLOW}暂无${NC} (可通过 '转发配置管理' 添加)"
        fi
    fi
    echo ""


}

#--- 定时任务管理功能 ---

# 初始化定时任务目录
init_cron_dir() {
    mkdir -p "$CRON_DIR"
    if [ ! -f "$CRON_TASKS_FILE" ]; then
        cat > "$CRON_TASKS_FILE" <<EOF
# Realm 定时任务配置文件
# 格式: ID|类型|间隔小时|下次执行时间|状态|创建时间
EOF
    fi
}

# 生成任务ID
generate_task_id() {
    local max_id=0
    if [ -f "$CRON_TASKS_FILE" ]; then
        while IFS='|' read -r id type interval next_time status created_time; do
            if [[ "$id" =~ ^[0-9]+$ ]] && [ "$id" -gt "$max_id" ]; then
                max_id=$id
            fi
        done < "$CRON_TASKS_FILE"
    fi
    echo $((max_id + 1))
}

# 获取GMT+8时间
get_gmt8_time() {
    TZ='GMT-8' date "$@"
}

# 获取安全级别显示文本
get_security_display() {
    local security_level="$1"
    local ws_path="$2"

    case "$security_level" in
        "standard")
            echo "默认传输"
            ;;
        "tls_self")
            echo "TLS自签证书"
            ;;
        "tls_ca")
            echo "TLS CA证书"
            ;;
        "ws_tls_self")
            if [ -n "$ws_path" ]; then
                echo "tls 自签证书+ws (路径: $ws_path)"
            else
                echo "tls 自签证书+ws"
            fi
            ;;
        "ws_tls_ca")
            if [ -n "$ws_path" ]; then
                echo "tls CA证书+ws (路径: $ws_path)"
            else
                echo "tls CA证书+ws"
            fi
            ;;
        "ws_"*)
            if [ -n "$ws_path" ]; then
                echo "$security_level (路径: $ws_path)"
            else
                echo "$security_level"
            fi
            ;;
        *)
            echo "$security_level"
            ;;
    esac
}

# 计算下次执行时间
calculate_next_time() {
    local interval_hours="$1"
    local current_time=$(TZ='GMT-8' date +%s)
    # 使用bc计算浮点数，支持小数小时
    local interval_seconds=$(echo "scale=0; $interval_hours * 3600 / 1" | bc)
    local next_time=$((current_time + interval_seconds))
    TZ='GMT-8' date -d "@$next_time" '+%Y-%m-%d %H:%M:%S'
}

# 添加定时重启任务
add_restart_task() {
    echo -e "${YELLOW}=== 添加定时重启 ===${NC}"
    echo ""

    while true; do
        read -p "请输入重启间隔(小时): " interval_hours
        # 改进的正则表达式：支持整数和小数，但不允许只有小数点
        if [[ "$interval_hours" =~ ^[0-9]+(\.[0-9]+)?$|^0\.[0-9]+$ ]] && (( $(echo "$interval_hours > 0 && $interval_hours <= 720" | bc -l) )); then
            break
        else
            echo -e "${RED}请输入有效的数字（如: 24 或 0.5），范围: 0.01-720小时${NC}"
        fi
    done

    # 计算下次执行时间
    local next_time=$(calculate_next_time "$interval_hours")
    local task_id=$(generate_task_id)
    local task_type="每${interval_hours}小时重启"
    local created_time=$(get_gmt8_time '+%Y-%m-%d %H:%M:%S')

    echo ""
    echo -e "${BLUE}下次重启时间: ${GREEN}$next_time (GMT+8)${NC}"
    echo -e "${BLUE}之后每 ${GREEN}$interval_hours${NC} ${BLUE}小时重启一次${NC}"
    echo ""

    read -p "确认添加？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 初始化目录
        init_cron_dir

        # 添加到任务文件
        echo "$task_id|$task_type|$interval_hours|$next_time|启用|$created_time" >> "$CRON_TASKS_FILE"

        # 添加到系统cron
        add_to_system_cron "$task_id" "$interval_hours"

        echo -e "${GREEN}✓ 定时重启任务已添加${NC}"
        echo -e "${BLUE}任务ID: $task_id${NC}"
    else
        echo -e "${YELLOW}操作已取消${NC}"
    fi

    echo ""
    read -p "按回车键继续..."
}

# 添加到系统cron
add_to_system_cron() {
    local task_id="$1"
    local interval_hours="$2"

    # 将小时转换为分钟，处理小数
    local interval_minutes=$(echo "scale=0; $interval_hours * 60 / 1" | bc)

    # 如果间隔小于1分钟，设为1分钟（cron最小精度限制）
    if [ "$interval_minutes" -lt 1 ]; then
        local actual_minutes=$(echo "scale=2; $interval_hours * 60" | bc)
        echo -e "${YELLOW}注意: 间隔 ${interval_hours} 小时 = ${actual_minutes} 分钟，小于1分钟${NC}"
        echo -e "${YELLOW}已自动调整为1分钟（cron最小精度限制）${NC}"
        interval_minutes=1
    fi

    # 创建cron任务脚本
    local cron_script="/etc/realm/cron_restart_${task_id}.sh"
    cat > "$cron_script" <<EOF
#!/bin/bash
# Realm 定时重启脚本 - 任务ID: $task_id

# 内置日志管理：控制日志文件大小
LOG_FILE="/var/log/realm_cron.log"
if [ -f "\$LOG_FILE" ]; then
    FILE_SIZE=\$(stat -f%z "\$LOG_FILE" 2>/dev/null || stat -c%s "\$LOG_FILE" 2>/dev/null || echo 0)
    if [ "\$FILE_SIZE" -gt 10485760 ]; then  # 10MB
        tail -c 5242880 "\$LOG_FILE" > "\${LOG_FILE}.tmp" 2>/dev/null && mv "\${LOG_FILE}.tmp" "\$LOG_FILE"
    fi
fi

# 检查服务状态
if systemctl is-active realm >/dev/null 2>&1; then
    echo "\$(TZ='GMT-8' date): 执行定时重启 - 任务ID: $task_id" >> /var/log/realm_cron.log
    systemctl restart realm
    if [ \$? -eq 0 ]; then
        echo "\$(TZ='GMT-8' date): 重启成功" >> /var/log/realm_cron.log
    else
        echo "\$(TZ='GMT-8' date): 重启失败" >> /var/log/realm_cron.log
    fi
else
    echo "\$(TZ='GMT-8' date): 服务未运行，跳过重启 - 任务ID: $task_id" >> /var/log/realm_cron.log
fi

# 更新下次执行时间
# 检查是否为整数小时，优先使用小时格式
if [[ "${interval_hours}" =~ ^[0-9]+$ ]]; then
    # 整数小时，直接使用小时计算
    next_time=\$(TZ='GMT-8' date -d "+${interval_hours} hours" '+%Y-%m-%d %H:%M:%S')
else
    # 小数小时，转换为分钟计算
    interval_minutes=\$(echo "scale=0; ${interval_hours} * 60 / 1" | bc)
    next_time=\$(TZ='GMT-8' date -d "+\${interval_minutes} minutes" '+%Y-%m-%d %H:%M:%S')
fi
sed -i "s/^$task_id|\\([^|]*\\)|\\([^|]*\\)|\\([^|]*\\)|/\$task_id|\\1|\\2|\$next_time|/" "$CRON_TASKS_FILE"
EOF

    chmod +x "$cron_script"

    # 添加到crontab - 使用标准cron格式，优先使用能整除的最大单位
    local cron_entry

    # 检查是否为整数小时
    if [[ "$interval_hours" =~ ^[0-9]+$ ]] && [ "$interval_minutes" -ge 60 ]; then
        # 整数小时，使用小时格式
        local interval_hours_int=$(echo "scale=0; $interval_hours / 1" | bc)
        if [ "$interval_hours_int" -lt 24 ]; then
            cron_entry="0 */$interval_hours_int * * * $cron_script"
        else
            # 大于24小时，计算天数间隔
            local interval_days=$((interval_hours_int/24))
            if [ "$interval_days" -lt 1 ]; then
                interval_days=1
            fi
            cron_entry="0 0 */$interval_days * * $cron_script"
        fi
    else
        # 非整数小时或小于1小时，使用分钟间隔
        cron_entry="*/$interval_minutes * * * * $cron_script"
    fi

    (crontab -l 2>/dev/null; echo "# Realm restart task $task_id"; echo "$cron_entry") | crontab -
}



# 删除任务
delete_task() {
    echo -e "${YELLOW}=== 删除定时任务 ===${NC}"
    echo ""

    # 显示当前任务
    if ! display_task_list; then
        echo ""
        read -p "按回车键继续..."
        return
    fi

    echo ""
    read -p "请输入要删除的任务ID: " task_id

    if [[ ! "$task_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的任务ID${NC}"
        echo ""
        read -p "按回车键继续..."
        return
    fi

    # 查找任务信息
    local task_info=$(grep "^$task_id|" "$CRON_TASKS_FILE")
    if [ -z "$task_info" ]; then
        echo -e "${RED}任务ID $task_id 不存在${NC}"
        echo ""
        read -p "按回车键继续..."
        return
    fi

    local task_type=$(echo "$task_info" | cut -d'|' -f2)

    echo ""
    read -p "确认删除任务\"$task_type\"？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 从任务文件中删除
        sed -i "/^$task_id|/d" "$CRON_TASKS_FILE"

        # 从系统cron中删除
        remove_from_system_cron "$task_id"

        echo -e "${GREEN}✓ 任务已删除${NC}"
    else
        echo -e "${YELLOW}操作已取消${NC}"
    fi

    echo ""
    read -p "按回车键继续..."
}

# 从系统cron中删除任务
remove_from_system_cron() {
    local task_id="$1"

    # 删除cron脚本
    local cron_script="/etc/realm/cron_restart_${task_id}.sh"
    if [ -f "$cron_script" ]; then
        rm -f "$cron_script"
    fi

    # 从crontab中删除相关条目
    crontab -l 2>/dev/null | grep -v "# Realm restart task $task_id" | grep -v "cron_restart_${task_id}.sh" | crontab -
}

# 显示任务列表（避免代码重复）
display_task_list() {
    init_cron_dir

    if [ ! -s "$CRON_TASKS_FILE" ] || [ $(grep -v '^#' "$CRON_TASKS_FILE" | wc -l) -eq 0 ]; then
        echo -e "${GRAY}暂无定时任务${NC}"
        return 1
    fi

    printf "%-4s %-20s %-25s %-8s\n" "ID" "类型" "下次执行时间(GMT+8)" "状态"
    echo "---------------------------------------------------------------------"

    while IFS='|' read -r id type interval next_time status created_time; do
        if [[ "$id" =~ ^[0-9]+$ ]]; then
            printf "%-4s %-20s %-25s %-8s\n" "$id" "$type" "$next_time" "$status"
        fi
    done < "$CRON_TASKS_FILE"

    return 0
}

# 定时任务管理菜单
cron_management_menu() {
    while true; do
        clear
        echo -e "${GREEN}=== 定时任务管理(DDNS 变更需要重启刷新) ===${NC}"
        echo ""

        # 直接显示当前任务列表
        display_task_list

        echo ""
        echo "请选择操作:"
        echo -e "${BLUE}1.${NC} 添加定时重启"
        echo -e "${RED}2.${NC} 删除任务"
        echo -e "${YELLOW}3.${NC} 返回主菜单"
        echo ""

        read -p "请输入选择 [1-3]: " choice
        echo ""

        case $choice in
            1)
                add_restart_task
                ;;
            2)
                delete_task
                ;;
            3)
                break
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-3${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 下载中转网络链路测试脚本
download_speedtest_script() {
    local script_url="https://raw.githubusercontent.com/zywe03/realm-xwPF/main/speedtest.sh"
    local target_path="/etc/realm/speedtest.sh"

    echo -e "${YELLOW}首次使用测速功能，正在下载测速脚本...${NC}"

    # 创建目录
    mkdir -p "$(dirname "$target_path")"

    # 使用多源下载机制
    local sources=(
        ""  # 官方源
        "https://proxy.vvvv.ee/"
        "https://ghproxy.com/"
    )

    local download_success=false
    for prefix in "${sources[@]}"; do
        local full_url="${prefix}${script_url}"
        echo -e "${BLUE}尝试下载: ${full_url}${NC}"

        if curl -fsSL --connect-timeout 10 --max-time 30 "$full_url" -o "$target_path"; then
            chmod +x "$target_path"
            echo -e "${GREEN}✓ 测速脚本下载成功${NC}"
            download_success=true
            break
        else
            echo -e "${RED}✗ 下载失败，尝试下一个源...${NC}"
        fi
    done

    if [ "$download_success" = false ]; then
        echo -e "${RED}✗ 所有下载源均失败，请检查网络连接${NC}"
        return 1
    fi

    return 0
}

# 中转网络链路测试菜单
speedtest_menu() {
    local speedtest_script="/etc/realm/speedtest.sh"

    # 检查测速脚本是否存在
    if [ ! -f "$speedtest_script" ]; then
        if ! download_speedtest_script; then
            echo -e "${RED}无法下载测速脚本，功能暂时不可用${NC}"
            read -p "按回车键返回主菜单..."
            return 1
        fi
    fi

    # 检查脚本是否可执行
    if [ ! -x "$speedtest_script" ]; then
        chmod +x "$speedtest_script"
    fi

    # 调用测速脚本
    echo -e "${BLUE}启动中转工具...${NC}"
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
        echo -e "${GREEN}=== xwPF Realm全功能一键脚本 v1.0.0 ===${NC}"
        echo -e "${GREEN}作者主页:https://zywe.de${NC}"
        echo -e "${GREEN}项目开源:https://github.com/zywe03/realm-xwPF${NC}"
        echo -e "${GREEN}一个开箱即用、轻量可靠、灵活可控的 Realm 转发管理工具${NC}"
        echo -e "${GREEN}原生realm的全部功能+故障转移 | 快捷命令: pf${NC}"

        # 显示当前状态
        show_brief_status

        echo "请选择操作:"
        echo -e "${GREEN}1.${NC} 安装(更新)程序,脚本"
        echo -e "${BLUE}2.${NC} 转发配置管理"
        echo -e "${GREEN}3.${NC} 重启服务"
        echo -e "${GREEN}4.${NC} 停止服务"
        echo -e "${YELLOW}5.${NC} 定时任务管理"
        echo -e "${GREEN}6.${NC} 查看日志"
        echo -e "${BLUE}7.${NC} 中转网络链路测试"
        echo -e "${RED}8.${NC} 卸载服务"
        echo -e "${YELLOW}9.${NC} 退出"
        echo ""

        read -p "请输入选择 [1-9]: " choice
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
                cron_management_menu
                ;;
            6)
                check_dependencies
                echo -e "${YELLOW}实时查看 Realm 日志 (按 Ctrl+C 返回菜单):${NC}"
                echo ""
                journalctl -u realm -f --no-pager
                ;;
            7)
                check_dependencies
                speedtest_menu
                ;;
            8)
                check_dependencies
                uninstall_realm
                read -p "按回车键继续..."
                ;;
            9)
                echo -e "${BLUE}感谢使用 Realm 端口转发管理脚本！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-9${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 内置清理机制（优雅管理临时文件和缓存）
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
        local letter_index=0
        declare -A letter_to_port

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

                    local letter=$(printf "\\$(printf '%03o' $((65 + letter_index)))")
                    letter_to_port[$letter]="$port_key"
                    letter_index=$((letter_index + 1))

                    # 获取故障转移状态
                    local failover_status="${port_failover_status[$port_key]}"
                    local status_text="关闭"
                    local status_color="${RED}"

                    if [ "$failover_status" = "true" ]; then
                        status_text="开启"
                        status_color="${GREEN}"
                    fi

                    echo -e "${GREEN}$letter.${NC} ${port_configs[$port_key]} (端口: $port_key) - $target_count个目标服务器 - 故障转移: ${status_color}$status_text${NC}"
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
        read -p "请输入要切换故障转移状态的规则字母: " choice

        if [ -z "$choice" ]; then
            return
        fi

        choice=$(echo "$choice" | tr '[:lower:]' '[:upper:]')

        if [ -z "${letter_to_port[$choice]}" ]; then
            echo -e "${RED}无效的规则字母${NC}"
            read -p "按回车键继续..."
            continue
        fi

        local selected_port="${letter_to_port[$choice]}"
        local rule_name="${port_configs[$selected_port]}"

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
        # 降级方案：轮询检查
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

# 健康检查函数
check_target_health() {
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
        if check_target_health "$target" "$REMOTE_PORT" "${CONNECTION_TIMEOUT:-3}"; then
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

    # 查找主脚本 - 参考成功案例的分阶段查找
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
        local rule_letters=()
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

                # 生成字母A、B、C等
                local letter_index=${#rule_letters[@]}
                local letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                local letter=${letters:$letter_index:1}
                rule_letters+=("$letter")
                rule_ports+=("$port_key")
                rule_names+=("${port_configs[$port_key]}")

                local balance_mode="${port_balance_modes[$port_key]}"
                echo -e "${GREEN}$letter.${NC} ${port_configs[$port_key]} (端口: $port_key) [$balance_mode] - $target_count个目标服务器"
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
        read -p "请输入规则字母 [${rule_letters[0]}-${rule_letters[-1]}] (大小写均可，或按回车返回): " selected_letter

        if [ -z "$selected_letter" ]; then
            break
        fi

        # 转换为大写进行比较
        selected_letter=$(echo "$selected_letter" | tr '[:lower:]' '[:upper:]')

        # 查找选择的规则组
        local selected_index=-1
        for i in "${!rule_letters[@]}"; do
            if [ "${rule_letters[i]}" = "$selected_letter" ]; then
                selected_index=$i
                break
            fi
        done

        if [ "$selected_index" -eq -1 ]; then
            echo -e "${RED}无效的规则字母${NC}"
            read -p "按回车键继续..."
            continue
        fi

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

# 配置规则权重（保留原函数作为兼容）
configure_rule_weights() {
    local rule_file="$1"
    local rule_name="$2"

    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}读取规则文件失败${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 如果是单目标，提示无需配置权重
    IFS=',' read -ra host_array <<< "$REMOTE_HOST"
    local target_count=${#host_array[@]}

    if [ "$target_count" -eq 1 ]; then
        echo -e "${YELLOW}该规则只有一个目标服务器，无需配置权重${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 调用端口组权重配置
    configure_port_group_weights "$LISTEN_PORT" "$rule_name" "$REMOTE_HOST:$REMOTE_PORT" "$WEIGHTS"
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

# 预览权重配置（保留原函数作为兼容）
preview_weight_config() {
    local rule_file="$1"
    local rule_name="$2"
    local weight_input="$3"
    shift 3
    local host_array=("$@")

    # 重新读取规则文件获取端口信息
    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}读取规则文件失败${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 调用端口组权重预览
    preview_port_group_weight_config "$LISTEN_PORT" "$rule_name" "$weight_input" "${host_array[@]}"
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

# 应用权重配置（保留原函数作为兼容）
apply_weight_config() {
    local rule_file="$1"
    local weight_input="$2"

    # 读取规则文件获取端口信息
    if ! read_rule_file "$rule_file"; then
        echo -e "${RED}读取规则文件失败${NC}"
        read -p "按回车键返回..."
        return
    fi

    # 调用端口组权重应用
    apply_port_group_weight_config "$LISTEN_PORT" "$weight_input"
}

main "$@"