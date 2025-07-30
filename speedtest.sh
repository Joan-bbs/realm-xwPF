#!/bin/bash

# 中转网络链路测试工具
# 作者: zywe
# 项目: https://github.com/zywe03/realm-xwPF

# 颜色定义 (与xwPF.sh保持一致)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# 全局变量
TARGET_IP=""
TARGET_PORT="5201"
TEST_DURATION="30"
ROLE=""

# 全局测试结果数据结构
declare -A TEST_RESULTS=(
    # 延迟测试结果
    ["latency_min"]=""
    ["latency_avg"]=""
    ["latency_max"]=""
    ["latency_jitter"]=""
    ["packet_sent"]=""
    ["packet_received"]=""

    # TCP上行测试结果
    ["tcp_up_speed_mbps"]=""
    ["tcp_up_speed_mibs"]=""
    ["tcp_up_transfer"]=""
    ["tcp_up_retrans"]=""
    ["tcp_up_congestion"]=""

    # TCP下行测试结果
    ["tcp_down_speed_mbps"]=""
    ["tcp_down_speed_mibs"]=""
    ["tcp_down_transfer"]=""
    ["tcp_down_retrans"]=""
    ["tcp_down_congestion"]=""

    # UDP上行测试结果
    ["udp_up_speed_mbps"]=""
    ["udp_up_speed_mibs"]=""
    ["udp_up_loss"]=""
    ["udp_up_jitter"]=""

    # UDP下行测试结果
    ["udp_down_speed_mbps"]=""
    ["udp_down_speed_mibs"]=""
    ["udp_down_loss"]=""
    ["udp_down_jitter"]=""

    # 路由分析结果
    ["route_as_path"]=""
    ["route_isp_path"]=""
    ["route_geo_path"]=""
    ["route_map_url"]=""
)

# 辅助函数：安全设置测试结果
set_test_result() {
    local key="$1"
    local value="$2"
    if [ -n "$value" ] && [ "$value" != "N/A" ]; then
        TEST_RESULTS["$key"]="$value"
    else
        TEST_RESULTS["$key"]=""
    fi
}

# 辅助函数：格式化显示测试结果
format_test_result() {
    local key="$1"
    local default_msg="$2"
    if [ -n "${TEST_RESULTS[$key]}" ]; then
        echo "${TEST_RESULTS[$key]}"
    else
        echo "$default_msg"
    fi
}

# 初始化测试结果数据结构
init_test_results() {
    for key in "${!TEST_RESULTS[@]}"; do
        TEST_RESULTS["$key"]=""
    done
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限运行${NC}"
        exit 1
    fi
}

# 工具配置数组 - 定义所有需要的工具
declare -A REQUIRED_TOOLS=(
    ["iperf3"]="apt:iperf3"
    ["fping"]="apt:fping"
    ["hping3"]="apt:hping3"
    ["jq"]="apt:jq"
    ["bc"]="apt:bc"
    ["nexttrace"]="custom:nexttrace"
    ["nc"]="apt:netcat-openbsd"
)

# 工具状态数组
declare -A TOOL_STATUS=()

# 记录初始安装状态的文件
INITIAL_STATUS_FILE="/tmp/speedtest_initial_status.txt"

# 检查单个工具是否存在
check_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# 记录初始工具状态到文件
record_initial_status() {
    # 如果状态文件已存在且是今天创建的，则不重新生成
    if [ -f "$INITIAL_STATUS_FILE" ]; then
        local file_date=$(date -r "$INITIAL_STATUS_FILE" +%Y%m%d 2>/dev/null || echo "19700101")
        local today=$(date +%Y%m%d)
        if [ "$file_date" = "$today" ]; then
            return 0
        fi
    fi

    # 重新生成状态文件
    rm -f "$INITIAL_STATUS_FILE"
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        if check_tool "$tool"; then
            echo "$tool=installed" >> "$INITIAL_STATUS_FILE"
        else
            echo "$tool=missing" >> "$INITIAL_STATUS_FILE"
        fi
    done
}

# 检测所有工具状态
detect_all_tools() {
    for tool in "${!REQUIRED_TOOLS[@]}"; do
        if check_tool "$tool"; then
            TOOL_STATUS["$tool"]="installed"
        else
            TOOL_STATUS["$tool"]="missing"
        fi
    done
}

# 获取缺失的工具列表
get_missing_tools() {
    local missing_tools=()
    for tool in "${!TOOL_STATUS[@]}"; do
        if [ "${TOOL_STATUS[$tool]}" = "missing" ]; then
            missing_tools+=("$tool")
        fi
    done
    echo "${missing_tools[@]}"
}

# 获取已安装的工具列表
get_installed_tools() {
    local installed_tools=()
    for tool in "${!TOOL_STATUS[@]}"; do
        if [ "${TOOL_STATUS[$tool]}" = "installed" ]; then
            installed_tools+=("$tool")
        fi
    done
    echo "${installed_tools[@]}"
}

# 获取新安装的工具列表（排除初始已有的）
get_newly_installed_tools() {
    local newly_installed_tools=()

    if [ -f "$INITIAL_STATUS_FILE" ]; then
        for tool in "${!TOOL_STATUS[@]}"; do
            if [ "${TOOL_STATUS[$tool]}" = "installed" ]; then
                # 检查初始状态文件中的记录
                local initial_status=$(grep "^$tool=" "$INITIAL_STATUS_FILE" 2>/dev/null | cut -d'=' -f2)
                if [ "$initial_status" = "missing" ]; then
                    newly_installed_tools+=("$tool")
                fi
            fi
        done
    else
        # 如果没有初始状态文件，返回所有已安装的工具
        for tool in "${!TOOL_STATUS[@]}"; do
            if [ "${TOOL_STATUS[$tool]}" = "installed" ]; then
                newly_installed_tools+=("$tool")
            fi
        done
    fi

    echo "${newly_installed_tools[@]}"
}

# 检查工具完整性
check_tools_completeness() {
    local missing_tools=($(get_missing_tools))
    if [ ${#missing_tools[@]} -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# 安装nexttrace
install_nexttrace() {
    echo -e "${YELLOW}正在安装 nexttrace...${NC}"

    # 检测系统架构
    local arch=$(uname -m)
    local os="linux"
    local download_url=""

    case $arch in
        x86_64)
            download_url="https://github.com/sjlleo/nexttrace/releases/latest/download/nexttrace_linux_amd64"
            ;;
        aarch64|arm64)
            download_url="https://github.com/sjlleo/nexttrace/releases/latest/download/nexttrace_linux_arm64"
            ;;
        armv7l)
            download_url="https://github.com/sjlleo/nexttrace/releases/latest/download/nexttrace_linux_armv7"
            ;;
        *)
            echo -e "${RED}✗ 不支持的系统架构: $arch${NC}"
            return 1
            ;;
    esac

    # 多源下载nexttrace
    local sources=(
        ""  # 官方源
        "https://ghproxy.com/"
        "https://proxy.vvvv.ee/"
    )

    local download_success=false
    for prefix in "${sources[@]}"; do
        local full_url="${prefix}${download_url}"
        echo -e "${BLUE}尝试下载: ${full_url}${NC}"

        if curl -fsSL --connect-timeout 10 --max-time 60 "$full_url" -o /usr/local/bin/nexttrace; then
            chmod +x /usr/local/bin/nexttrace
            echo -e "${GREEN}✅ nexttrace 下载成功${NC}"
            download_success=true
            break
        else
            echo -e "${RED}✗ 下载失败，尝试下一个源...${NC}"
        fi
    done

    if [ "$download_success" = true ]; then
        return 0
    else
        echo -e "${RED}✗ 所有下载源均失败${NC}"
        return 1
    fi
}

# 安装单个APT工具
install_apt_tool() {
    local tool="$1"
    local package="$2"

    echo -e "${BLUE}🔧 安装 $tool...${NC}"
    if apt-get install -y "$package" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $tool 安装成功${NC}"
        TOOL_STATUS["$tool"]="installed"
        return 0
    else
        echo -e "${RED}✗ $tool 安装失败${NC}"
        return 1
    fi
}

# 安装自定义工具
install_custom_tool() {
    local tool="$1"

    case "$tool" in
        "nexttrace")
            if install_nexttrace; then
                echo -e "${GREEN}✅ nexttrace 安装成功${NC}"
                TOOL_STATUS["nexttrace"]="installed"
                return 0
            else
                echo -e "${RED}✗ nexttrace 安装失败${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${RED}✗ 未知的自定义工具: $tool${NC}"
            return 1
            ;;
    esac
}

# 安装缺失的工具
install_missing_tools() {
    local missing_tools=($(get_missing_tools))

    if [ ${#missing_tools[@]} -eq 0 ]; then
        return 0
    fi

    echo -e "${YELLOW}📦 安装缺失工具: ${missing_tools[*]}${NC}"

    # 更新包列表
    apt-get update >/dev/null 2>&1

    local install_failed=false

    for tool in "${missing_tools[@]}"; do
        local tool_config="${REQUIRED_TOOLS[$tool]}"
        local install_type="${tool_config%%:*}"
        local package_name="${tool_config##*:}"

        case "$install_type" in
            "apt")
                if ! install_apt_tool "$tool" "$package_name"; then
                    install_failed=true
                fi
                ;;
            "custom")
                if ! install_custom_tool "$tool"; then
                    install_failed=true
                fi
                ;;
            *)
                install_failed=true
                ;;
        esac
    done

    if [ "$install_failed" = false ]; then
        echo -e "${GREEN}✅ 工具安装完成${NC}"
    fi
}

# 主安装函数
install_required_tools() {
    # 记录初始状态
    record_initial_status

    # 检测当前工具状态
    detect_all_tools

    # 检查完整性
    if check_tools_completeness; then
        return 0
    fi

    # 安装缺失的工具
    install_missing_tools
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    elif [[ $ip =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        # 域名格式
        return 0
    else
        return 1
    fi
}

# 获取本机IP
get_public_ip() {
    local ip=""

    # 优先使用ipinfo.io
    ip=$(curl -s --connect-timeout 5 --max-time 10 "https://ipinfo.io/ip" 2>/dev/null | tr -d '\n\r ')
    if validate_ip "$ip"; then
        echo "$ip"
        return 0
    fi

    # 备用cloudflare trace
    ip=$(curl -s --connect-timeout 5 --max-time 10 "https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null | grep "ip=" | cut -d'=' -f2 | tr -d '\n\r ')
    if validate_ip "$ip"; then
        echo "$ip"
        return 0
    fi

    return 1
}

# 验证端口号
validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# 测试连通性
test_connectivity() {
    local ip="$1"
    local port="$2"

    if nc -z -w3 "$ip" "$port" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 落地机模式 - 启动服务端
landing_server_mode() {
    clear
    echo -e "${GREEN}=== 落地机模式 ===${NC}"
    echo ""

    # 输入监听端口
    while true; do
        read -p "监听测试端口 [默认5201]: " input_port
        if [ -z "$input_port" ]; then
            TARGET_PORT="5201"
            break
        elif validate_port "$input_port"; then
            TARGET_PORT="$input_port"
            break
        else
            echo -e "${RED}无效端口号，请输入1-65535之间的数字${NC}"
        fi
    done

    echo ""
    echo -e "${YELLOW}启动服务中...${NC}"

    # 停止可能存在的iperf3进程
    pkill -f "iperf3.*-s.*-p.*$TARGET_PORT" 2>/dev/null

    # 启动iperf3服务端
    if iperf3 -s -p "$TARGET_PORT" -D >/dev/null 2>&1; then
        echo -e "${GREEN}✅ iperf3服务已启动 (端口$TARGET_PORT)${NC}"
    else
        echo -e "${RED}✗ iperf3服务启动失败${NC}"
        exit 1
    fi

    # 获取本机IP
    local local_ip=$(get_public_ip || echo "获取失败")

    echo -e "${BLUE}📋 落地机信息${NC}"
    echo -e "   IP地址: ${GREEN}$local_ip${NC}"
    echo -e "   端口: ${GREEN}$TARGET_PORT${NC}"
    echo ""
    echo -e "${YELLOW}💡 请在中转机输入落地机IP: ${GREEN}$local_ip${NC}"
    echo -e "${YELLOW}   请到中转机选择1. 中转机 (发起测试)...${NC}"

    echo ""
    echo -e "${WHITE}按任意键停止服务${NC}"

    # 等待用户按键
    read -n 1 -s

    # 停止服务
    pkill -f "iperf3.*-s.*-p.*$TARGET_PORT" 2>/dev/null
    echo ""
    echo -e "${GREEN}服务已停止${NC}"
}

# 执行延迟测试
run_latency_tests() {
    echo -e "${YELLOW}🟢 延迟测试${NC}"
    echo ""

    # 使用hping3进行TCP延迟测试
    if check_tool "hping3"; then
        echo -e "${GREEN}🚀 TCP应用层延迟测试 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"
        echo ""

        # 后台执行测试，前台显示进度条
        local temp_result=$(mktemp)
        (hping3 -c 20 -i 1 -S -p "$TARGET_PORT" "$TARGET_IP" > "$temp_result" 2>&1) &
        local test_pid=$!

        show_progress_bar "20" "TCP延迟测试"

        # 等待测试完成
        wait $test_pid
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            local result=$(cat "$temp_result")
            echo ""
            echo -e "${BLUE}📋 测试数据:${NC}"
            echo "$result"

            # 解析TCP延迟统计和包统计
            local stats_line=$(echo "$result" | grep "round-trip")
            local packet_line=$(echo "$result" | grep "packets transmitted")

            if [ -n "$stats_line" ] && [ -n "$packet_line" ]; then
                # 提取延迟数据: min/avg/max
                local stats=$(echo "$stats_line" | awk -F'min/avg/max = ' '{print $2}' | awk '{print $1}')
                local min_delay=$(echo "$stats" | cut -d'/' -f1)
                local avg_delay=$(echo "$stats" | cut -d'/' -f2)
                local max_delay=$(echo "$stats" | cut -d'/' -f3)

                # 提取包统计数据
                local transmitted=$(echo "$packet_line" | awk '{print $1}')
                local received=$(echo "$packet_line" | awk '{print $4}')
                local loss_percent=$(echo "$packet_line" | grep -o '[0-9-]\+%' | head -1)

                # 计算重复包数量
                local duplicate_count=0
                if [ "$received" -gt "$transmitted" ]; then
                    duplicate_count=$((received - transmitted))
                fi

                # 计算延迟抖动 (最高延迟 - 最低延迟)
                local jitter=$(awk "BEGIN {printf \"%.1f\", $max_delay - $min_delay}")

                # 提取TTL范围
                local ttl_values=$(echo "$result" | grep "ttl=" | grep -o "ttl=[0-9]\+" | grep -o "[0-9]\+" | sort -n | uniq)
                local ttl_min=$(echo "$ttl_values" | head -1)
                local ttl_max=$(echo "$ttl_values" | tail -1)
                local ttl_range="${ttl_min}"
                if [ "$ttl_min" != "$ttl_max" ]; then
                    ttl_range="${ttl_min}-${ttl_max}"
                fi

                # 验证提取结果
                if [ -n "$min_delay" ] && [ -n "$avg_delay" ] && [ -n "$max_delay" ]; then
                    echo -e "${GREEN}TCP应用层延迟测试完成${NC}"
                    echo -e "使用指令: ${YELLOW}hping3 -c 20 -i 1 -S -p $TARGET_PORT $TARGET_IP${NC}"
                    echo ""
                    echo -e "${BLUE}📊 测试结果${NC}"
                    echo ""
                    echo -e "TCP延迟: ${YELLOW}最低${min_delay}ms / 平均${avg_delay}ms / 最高${max_delay}ms${NC}"

                    # 构建收发统计信息
                    local packet_info="${transmitted} 发送 / ${received} 接收"
                    if [ "$duplicate_count" -gt 0 ]; then
                        packet_info="${packet_info} (含 ${duplicate_count} 个异常包)"
                    fi

                    echo -e "收发统计: ${YELLOW}${packet_info}${NC} | 抖动: ${YELLOW}${jitter}ms${NC} | TTL范围: ${YELLOW}${ttl_range}${NC}"

                    # 收集延迟测试数据
                    set_test_result "latency_min" "$min_delay"
                    set_test_result "latency_avg" "$avg_delay"
                    set_test_result "latency_max" "$max_delay"
                    set_test_result "latency_jitter" "$jitter"
                    set_test_result "packet_sent" "$transmitted"
                    set_test_result "packet_received" "$received"

                    FPING_SUCCESS=true
                    HPING_SUCCESS=true
                else
                    echo -e "${RED}❌ 数据提取失败${NC}"
                    FPING_SUCCESS=false
                    HPING_SUCCESS=false
                fi
            else
                echo -e "${RED}❌ 未找到统计行${NC}"
                FPING_SUCCESS=false
                HPING_SUCCESS=false
            fi
        else
            echo -e "${RED}❌ 测试执行失败 (可能需要管理员权限)${NC}"
            FPING_SUCCESS=false
            HPING_SUCCESS=false
        fi

        rm -f "$temp_result"
        echo ""
    else
        echo -e "${YELLOW}⚠️  hping3工具不可用，跳过TCP延迟测试${NC}"
        FPING_SUCCESS=false
        HPING_SUCCESS=false
    fi
}

# 显示进度条
show_progress_bar() {
    local duration=$1
    local test_name="$2"

    echo -e "${BLUE}🔄 ${test_name} 进行中...${NC}"

    for ((i=1; i<=duration; i++)); do
        printf "\r  ⏱️ %d/%d秒" $i $duration
        sleep 1
    done
    echo ""
}

# 解析iperf3数据的通用函数
parse_iperf3_data() {
    local line="$1"
    local data_type="$2"  # "transfer" 或 "bitrate" 或 "retrans" 或 "jitter" 或 "loss"

    case "$data_type" in
        "transfer")
            echo "$line" | grep -o '[0-9.]\+\s*MBytes' | head -1 | grep -o '[0-9.]\+'
            ;;
        "bitrate")
            echo "$line" | grep -o '[0-9.]\+\s*MBytes/sec' | head -1 | grep -o '[0-9.]\+'
            ;;
        "retrans")
            echo "$line" | grep -o '[0-9]\+\s*sender$' | grep -o '[0-9]\+' || echo "0"
            ;;
        "jitter")
            echo "$line" | grep -o '[0-9.]\+\s*ms' | head -1 | grep -o '[0-9.]\+'
            ;;
        "loss")
            echo "$line" | grep -o '[0-9]\+/[0-9]\+\s*([0-9.]\+%)' | head -1
            ;;
        "cpu_local")
            echo "$line" | grep -o 'local/sender [0-9.]\+%' | grep -o '[0-9.]\+%'
            ;;
        "cpu_remote")
            echo "$line" | grep -o 'remote/receiver [0-9.]\+%' | grep -o '[0-9.]\+%'
            ;;
    esac
}

# 执行TCP上行带宽测试
run_tcp_single_thread_test() {
    echo -e "${GREEN}🚀 TCP上行带宽测试 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"
    echo ""

    # 后台执行测试，前台显示进度条
    local temp_result=$(mktemp)
    (iperf3 -c "$TARGET_IP" -p "$TARGET_PORT" -t "$TEST_DURATION" -f M -V 2>&1 > "$temp_result") &
    local test_pid=$!

    show_progress_bar "$TEST_DURATION" "TCP单线程测试"

    # 等待测试完成
    wait $test_pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        local result=$(cat "$temp_result")
        echo ""
        echo -e "${BLUE}📋 测试数据:${NC}"
        # 过滤掉开头和结尾的杂乱信息，保留核心测试数据
        echo "$result" | sed -n '/\[ *[0-9]\]/,/^$/p' | sed '/^- - - - -/,$d' | sed '/^$/d'

        # 解析最终结果
        local final_line=$(echo "$result" | grep "sender$" | tail -1)
        local cpu_line=$(echo "$result" | grep "CPU Utilization" | tail -1)

        if [ -n "$final_line" ]; then
            local final_transfer=$(parse_iperf3_data "$final_line" "transfer")
            local final_bitrate=$(parse_iperf3_data "$final_line" "bitrate")

            # 从整行中提取重传次数 (在sender行的倒数第二个字段)
            local final_retrans=$(echo "$final_line" | awk '{print $(NF-1)}')

            # 解析CPU使用率
            local cpu_local=""
            local cpu_remote=""
            if [ -n "$cpu_line" ]; then
                cpu_local=$(parse_iperf3_data "$cpu_line" "cpu_local")
                cpu_remote=$(parse_iperf3_data "$cpu_line" "cpu_remote")
            fi

            echo -e "${GREEN}TCP上行测试完成${NC}"
            echo -e "使用指令: ${YELLOW}iperf3 -c $TARGET_IP -p $TARGET_PORT -t $TEST_DURATION -f M -V${NC}"
            echo ""
            echo -e "${YELLOW}📊 测试结果${NC}"
            echo ""

            # 计算Mbps，MiB/s直接使用MBytes/sec值
            local mbps=$(awk "BEGIN {printf \"%.0f\", $final_bitrate * 8}")

            echo -e "平均发送速率 (Sender): ${YELLOW}${mbps:-N/A} Mbps${NC} (${YELLOW}${final_bitrate:-N/A} MiB/s${NC})          总传输数据量: ${YELLOW}${final_transfer:-N/A} MB${NC}"

            # 获取TCP拥塞控制算法
            local snd_congestion=$(echo "$result" | grep "snd_tcp_congestion" | awk '{print $2}')
            local rcv_congestion=$(echo "$result" | grep "rcv_tcp_congestion" | awk '{print $2}')

            if [ -n "$snd_congestion" ] && [ -n "$rcv_congestion" ]; then
                echo -e "TCP 拥塞控制算法: ${YELLOW}(发) ${snd_congestion} > (收) ${rcv_congestion}${NC}"
            elif [ -n "$snd_congestion" ]; then
                echo -e "TCP 拥塞控制算法: ${YELLOW}${snd_congestion}${NC}"
            else
                echo -e "TCP 拥塞控制算法: ${YELLOW}系统默认${NC}"
            fi

            # 显示重传次数（不计算重传率，避免估算误差）
            echo -e "重传次数: ${YELLOW}${final_retrans:-0} 次${NC}"

            # 显示CPU负载
            if [ -n "$cpu_local" ] && [ -n "$cpu_remote" ]; then
                echo -e "CPU 负载: 发送端 ${YELLOW}${cpu_local}${NC} 接收端 ${YELLOW}${cpu_remote}${NC}"
            fi

            echo -e "测试时长: ${YELLOW}${TEST_DURATION} 秒${NC}"

            # 收集TCP上行测试数据
            set_test_result "tcp_up_speed_mbps" "$mbps"
            set_test_result "tcp_up_speed_mibs" "$final_bitrate"
            set_test_result "tcp_up_transfer" "$final_transfer"
            set_test_result "tcp_up_retrans" "$final_retrans"
            if [ -n "$snd_congestion" ] && [ -n "$rcv_congestion" ]; then
                set_test_result "tcp_up_congestion" "(发) ${snd_congestion} > (收) ${rcv_congestion}"
            elif [ -n "$snd_congestion" ]; then
                set_test_result "tcp_up_congestion" "$snd_congestion"
            fi

            # 保存TCP Mbps值，四舍五入到10的倍数，用于UDP的-b参数
            local tcp_mbps_raw=$(awk "BEGIN {printf \"%.0f\", $final_bitrate * 8}")
            TCP_MBPS=$(awk "BEGIN {printf \"%.0f\", int(($tcp_mbps_raw + 5) / 10) * 10}")
            TCP_SINGLE_SUCCESS=true
        else
            echo -e "${RED}❌ 无法解析测试结果${NC}"
            TCP_SINGLE_SUCCESS=false
        fi
    else
        echo -e "${RED}❌ 测试执行失败${NC}"
        TCP_SINGLE_SUCCESS=false
    fi

    rm -f "$temp_result"
    echo ""
}

# 执行带宽测试
run_bandwidth_tests() {
    echo -e "${YELLOW}🟢 网络带宽性能测试${NC}"
    echo ""

    # 检查iperf3工具
    if ! check_tool "iperf3"; then
        echo -e "${YELLOW}⚠️  iperf3工具不可用，跳过带宽测试${NC}"
        TCP_SUCCESS=false
        UDP_SINGLE_SUCCESS=false
        UDP_DOWNLOAD_SUCCESS=false
        return
    fi

    # 检查连通性
    if ! nc -z -w3 "$TARGET_IP" "$TARGET_PORT" >/dev/null 2>&1; then
        echo -e "  ${RED}无法连接到目标服务器${NC}"
        echo -e "  ${YELLOW}请确认目标服务器运行: iperf3 -s -p $TARGET_PORT${NC}"
        TCP_SUCCESS=false
        UDP_SINGLE_SUCCESS=false
        UDP_DOWNLOAD_SUCCESS=false
        echo ""
        return
    fi

    # 执行TCP上行测试
    run_tcp_single_thread_test

    echo ""
    sleep 2

    # 执行UDP上行测试
    run_udp_single_test

    echo ""
    sleep 2

    # 执行TCP下行测试
    run_tcp_download_test

    echo ""
    sleep 2

    # 执行UDP下行测试
    run_udp_download_test
}

# 执行UDP上行测试
run_udp_single_test() {
    echo -e "${GREEN}🚀 UDP上行性能测试 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"
    echo ""

    # 根据TCP测试结果设置UDP目标带宽
    local udp_bandwidth="30M"  # 默认值
    if [ "$TCP_SINGLE_SUCCESS" = true ] && [ -n "$TCP_MBPS" ]; then
        # 直接使用TCP测试的Mbps值作为UDP目标带宽
        udp_bandwidth="${TCP_MBPS}M"
    fi

    # 后台执行测试，前台显示进度条
    local temp_result=$(mktemp)
    (iperf3 -c "$TARGET_IP" -p "$TARGET_PORT" -u -b "$udp_bandwidth" -t "$TEST_DURATION" -f M -V 2>&1 > "$temp_result") &
    local test_pid=$!

    show_progress_bar "$TEST_DURATION" "UDP单线程测试"

    # 等待测试完成
    wait $test_pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        local result=$(cat "$temp_result")
        echo ""
        echo -e "${BLUE}📋 测试数据:${NC}"
        # 过滤掉开头和结尾的杂乱信息，保留核心测试数据
        echo "$result" | sed -n '/\[ *[0-9]\]/,/^$/p' | sed '/^- - - - -/,$d' | sed '/^$/d'

        # 解析最终结果
        local sender_line=$(echo "$result" | grep "sender$" | tail -1)
        local receiver_line=$(echo "$result" | grep "receiver$" | tail -1)

        if [ -n "$sender_line" ]; then
            local final_transfer=$(parse_iperf3_data "$sender_line" "transfer")
            local final_bitrate=$(parse_iperf3_data "$sender_line" "bitrate")

            echo -e "${GREEN}UDP上行测试完成${NC}"
            echo -e "使用指令: ${YELLOW}iperf3 -c $TARGET_IP -p $TARGET_PORT -u -b $udp_bandwidth -t $TEST_DURATION -f M -V${NC}"
            echo ""
            echo -e "${YELLOW}📡 传输统计${NC}"
            echo ""

            # 解析接收端信息和CPU信息
            local cpu_line=$(echo "$result" | grep "CPU Utilization" | tail -1)
            local cpu_local=""
            local cpu_remote=""
            if [ -n "$cpu_line" ]; then
                cpu_local=$(parse_iperf3_data "$cpu_line" "cpu_local")
                cpu_remote=$(parse_iperf3_data "$cpu_line" "cpu_remote")
            fi

            if [ -n "$receiver_line" ]; then
                local receiver_transfer=$(parse_iperf3_data "$receiver_line" "transfer")
                local receiver_bitrate=$(parse_iperf3_data "$receiver_line" "bitrate")
                local jitter=$(parse_iperf3_data "$receiver_line" "jitter")
                local loss_info=$(parse_iperf3_data "$receiver_line" "loss")

                # 计算有效吞吐量 (接收端数据)，MiB/s直接使用MBytes/sec值
                local recv_mbps=$(awk "BEGIN {printf \"%.1f\", $receiver_bitrate * 8}")

                # 计算目标速率显示（与-b参数一致）
                local target_mbps=$(echo "$udp_bandwidth" | sed 's/M$//')

                echo -e "有效吞吐量 (吞吐率): ${YELLOW}${recv_mbps:-N/A} Mbps${NC} (${YELLOW}${receiver_bitrate:-N/A} MiB/s${NC})"
                echo -e "丢包率 (Packet Loss): ${YELLOW}${loss_info:-N/A}${NC}"
                echo -e "网络抖动 (Jitter): ${YELLOW}${jitter:-N/A} ms${NC}"

                # 显示CPU负载
                if [ -n "$cpu_local" ] && [ -n "$cpu_remote" ]; then
                    echo -e "CPU负载: 发送端 ${YELLOW}${cpu_local}${NC} 接收端 ${YELLOW}${cpu_remote}${NC}"
                fi

                echo -e "测试目标速率: ${YELLOW}${target_mbps} Mbps${NC}"

                # 收集UDP上行测试数据
                set_test_result "udp_up_speed_mbps" "$recv_mbps"
                set_test_result "udp_up_speed_mibs" "$receiver_bitrate"
                set_test_result "udp_up_loss" "$loss_info"
                set_test_result "udp_up_jitter" "$jitter"
            else
                echo -e "有效吞吐量 (吞吐率): ${YELLOW}N/A${NC}"
                echo -e "丢包率 (Packet Loss): ${YELLOW}N/A${NC}"
                echo -e "网络抖动 (Jitter): ${YELLOW}N/A${NC}"
                echo -e "CPU负载: ${YELLOW}N/A${NC}"
                echo -e "测试目标速率: ${YELLOW}N/A${NC}"
            fi
            UDP_SINGLE_SUCCESS=true
        else
            echo -e "${RED}❌ 无法解析测试结果${NC}"
            UDP_SINGLE_SUCCESS=false
        fi
    else
        echo -e "${RED}❌ 测试执行失败${NC}"
        UDP_SINGLE_SUCCESS=false
    fi

    rm -f "$temp_result"
    echo ""
}

# 执行TCP下行带宽测试
run_tcp_download_test() {
    echo -e "${GREEN}🚀 TCP下行带宽测试 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"
    echo ""

    # 后台执行测试，前台显示进度条
    local temp_result=$(mktemp)
    (iperf3 -c "$TARGET_IP" -p "$TARGET_PORT" -t "$TEST_DURATION" -f M -V -R 2>&1 > "$temp_result") &
    local test_pid=$!

    show_progress_bar "$TEST_DURATION" "TCP下行测试"

    # 等待测试完成
    wait $test_pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        local result=$(cat "$temp_result")
        echo ""
        echo -e "${BLUE}📋 测试数据:${NC}"
        # 过滤掉开头和结尾的杂乱信息，保留核心测试数据
        echo "$result" | sed -n '/\[ *[0-9]\]/,/^$/p' | sed '/^- - - - -/,$d' | sed '/^$/d'

        # 解析最终结果 - 下行测试需要使用receiver行数据
        local sender_line=$(echo "$result" | grep "sender$" | tail -1)
        local receiver_line=$(echo "$result" | grep "receiver$" | tail -1)
        local cpu_line=$(echo "$result" | grep "CPU Utilization" | tail -1)

        if [ -n "$receiver_line" ]; then
            # 使用receiver行数据（真实下行速率）
            local final_transfer=$(parse_iperf3_data "$receiver_line" "transfer")
            local final_bitrate=$(parse_iperf3_data "$receiver_line" "bitrate")

            # 重传次数仍从sender行获取
            local final_retrans=""
            if [ -n "$sender_line" ]; then
                final_retrans=$(echo "$sender_line" | awk '{print $(NF-1)}')
            fi

            # 解析CPU使用率
            local cpu_local=""
            local cpu_remote=""
            if [ -n "$cpu_line" ]; then
                cpu_local=$(parse_iperf3_data "$cpu_line" "cpu_local")
                cpu_remote=$(parse_iperf3_data "$cpu_line" "cpu_remote")
            fi

            echo -e "${GREEN}TCP下行测试完成${NC}"
            echo -e "使用指令: ${YELLOW}iperf3 -c $TARGET_IP -p $TARGET_PORT -t $TEST_DURATION -f M -V -R${NC}"
            echo ""
            echo -e "${YELLOW}📊 测试结果${NC}"
            echo ""

            # 计算Mbps，MiB/s直接使用MBytes/sec值
            local mbps=$(awk "BEGIN {printf \"%.0f\", $final_bitrate * 8}")

            echo -e "平均下行速率 (Receiver): ${YELLOW}${mbps:-N/A} Mbps${NC} (${YELLOW}${final_bitrate:-N/A} MiB/s${NC})          总传输数据量: ${YELLOW}${final_transfer:-N/A} MB${NC}"

            # 获取TCP拥塞控制算法
            local snd_congestion=$(echo "$result" | grep "snd_tcp_congestion" | awk '{print $2}')
            local rcv_congestion=$(echo "$result" | grep "rcv_tcp_congestion" | awk '{print $2}')

            if [ -n "$snd_congestion" ] && [ -n "$rcv_congestion" ]; then
                echo -e "TCP 拥塞控制算法: ${YELLOW}(发) ${snd_congestion} > (收) ${rcv_congestion}${NC}"
            elif [ -n "$snd_congestion" ]; then
                echo -e "TCP 拥塞控制算法: ${YELLOW}${snd_congestion}${NC}"
            else
                echo -e "TCP 拥塞控制算法: ${YELLOW}系统默认${NC}"
            fi

            # 显示重传次数（不计算重传率，避免估算误差）
            echo -e "重传次数: ${YELLOW}${final_retrans:-0} 次${NC}"

            # 显示CPU负载
            if [ -n "$cpu_local" ] && [ -n "$cpu_remote" ]; then
                echo -e "CPU 负载: 发送端 ${YELLOW}${cpu_local}${NC} 接收端 ${YELLOW}${cpu_remote}${NC}"
            fi

            echo -e "测试时长: ${YELLOW}${TEST_DURATION} 秒${NC}"

            # 收集TCP下行测试数据
            set_test_result "tcp_down_speed_mbps" "$mbps"
            set_test_result "tcp_down_speed_mibs" "$final_bitrate"
            set_test_result "tcp_down_transfer" "$final_transfer"
            set_test_result "tcp_down_retrans" "$final_retrans"

            # 收集TCP下行拥塞控制算法
            if [ -n "$snd_congestion" ] && [ -n "$rcv_congestion" ]; then
                set_test_result "tcp_down_congestion" "(发) ${snd_congestion} > (收) ${rcv_congestion}"
            elif [ -n "$snd_congestion" ]; then
                set_test_result "tcp_down_congestion" "$snd_congestion"
            fi

            # 保存TCP下行Mbps值，四舍五入到10的倍数，用于UDP下行的-b参数
            local tcp_download_mbps_raw=$(awk "BEGIN {printf \"%.0f\", $final_bitrate * 8}")
            TCP_DOWNLOAD_MBPS=$(awk "BEGIN {printf \"%.0f\", int(($tcp_download_mbps_raw + 5) / 10) * 10}")
            TCP_DOWNLOAD_SUCCESS=true
        else
            echo -e "${RED}❌ 无法解析测试结果${NC}"
            TCP_DOWNLOAD_SUCCESS=false
        fi
    else
        echo -e "${RED}❌ 测试执行失败${NC}"
        TCP_DOWNLOAD_SUCCESS=false
    fi

    rm -f "$temp_result"
    echo ""
}

# 执行UDP下行测试
run_udp_download_test() {
    echo -e "${GREEN}🚀 UDP下行性能测试 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"
    echo ""

    # 根据TCP下行测试结果设置UDP目标带宽
    local udp_bandwidth="30M"  # 默认值
    if [ "$TCP_DOWNLOAD_SUCCESS" = true ] && [ -n "$TCP_DOWNLOAD_MBPS" ]; then
        # 直接使用TCP下行测试的Mbps值作为UDP目标带宽
        udp_bandwidth="${TCP_DOWNLOAD_MBPS}M"
    fi

    # 后台执行测试，前台显示进度条
    local temp_result=$(mktemp)
    (iperf3 -c "$TARGET_IP" -p "$TARGET_PORT" -u -b "$udp_bandwidth" -t "$TEST_DURATION" -f M -V -R 2>&1 > "$temp_result") &
    local test_pid=$!

    show_progress_bar "$TEST_DURATION" "UDP下行测试"

    # 等待测试完成
    wait $test_pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        local result=$(cat "$temp_result")
        echo ""
        echo -e "${BLUE}📋 测试数据:${NC}"
        # 过滤掉开头和结尾的杂乱信息，保留核心测试数据
        echo "$result" | sed -n '/\[ *[0-9]\]/,/^$/p' | sed '/^- - - - -/,$d' | sed '/^$/d'

        # 解析最终结果
        local sender_line=$(echo "$result" | grep "sender$" | tail -1)
        local receiver_line=$(echo "$result" | grep "receiver$" | tail -1)

        if [ -n "$sender_line" ]; then
            echo -e "${GREEN}UDP下行测试完成${NC}"
            echo -e "使用指令: ${YELLOW}iperf3 -c $TARGET_IP -p $TARGET_PORT -u -b $udp_bandwidth -t $TEST_DURATION -f M -V -R${NC}"
            echo ""
            echo -e "${YELLOW}📡 传输统计${NC}"
            echo ""

            # 解析接收端信息和CPU信息
            local cpu_line=$(echo "$result" | grep "CPU Utilization" | tail -1)
            local cpu_local=""
            local cpu_remote=""
            if [ -n "$cpu_line" ]; then
                cpu_local=$(parse_iperf3_data "$cpu_line" "cpu_local")
                cpu_remote=$(parse_iperf3_data "$cpu_line" "cpu_remote")
            fi

            if [ -n "$receiver_line" ]; then
                local receiver_transfer=$(parse_iperf3_data "$receiver_line" "transfer")
                local receiver_bitrate=$(parse_iperf3_data "$receiver_line" "bitrate")
                local jitter=$(parse_iperf3_data "$receiver_line" "jitter")
                local loss_info=$(parse_iperf3_data "$receiver_line" "loss")

                # 计算有效吞吐量 (接收端数据)，MiB/s直接使用MBytes/sec值
                local recv_mbps=$(awk "BEGIN {printf \"%.1f\", $receiver_bitrate * 8}")

                # 计算目标速率显示（与-b参数一致）
                local target_mbps=$(echo "$udp_bandwidth" | sed 's/M$//')

                echo -e "有效吞吐量 (吞吐率): ${YELLOW}${recv_mbps:-N/A} Mbps${NC} (${YELLOW}${receiver_bitrate:-N/A} MiB/s${NC})"
                echo -e "丢包率 (Packet Loss): ${YELLOW}${loss_info:-N/A}${NC}"
                echo -e "网络抖动 (Jitter): ${YELLOW}${jitter:-N/A} ms${NC}"

                # 显示CPU负载
                if [ -n "$cpu_local" ] && [ -n "$cpu_remote" ]; then
                    echo -e "CPU负载: 发送端 ${YELLOW}${cpu_local}${NC} 接收端 ${YELLOW}${cpu_remote}${NC}"
                fi

                echo -e "测试目标速率: ${YELLOW}${target_mbps} Mbps${NC}"

                # 收集UDP下行测试数据
                set_test_result "udp_down_speed_mbps" "$recv_mbps"
                set_test_result "udp_down_speed_mibs" "$receiver_bitrate"
                set_test_result "udp_down_loss" "$loss_info"
                set_test_result "udp_down_jitter" "$jitter"
            else
                echo -e "有效吞吐量 (吞吐率): ${YELLOW}N/A${NC}"
                echo -e "丢包率 (Packet Loss): ${YELLOW}N/A${NC}"
                echo -e "网络抖动 (Jitter): ${YELLOW}N/A${NC}"
                echo -e "CPU负载: ${YELLOW}N/A${NC}"
                echo -e "测试目标速率: ${YELLOW}N/A${NC}"
            fi

            UDP_DOWNLOAD_SUCCESS=true
        else
            echo -e "${RED}❌ 无法解析测试结果${NC}"
            UDP_DOWNLOAD_SUCCESS=false
        fi
    else
        echo -e "${RED}❌ 测试执行失败${NC}"
        UDP_DOWNLOAD_SUCCESS=false
    fi

    rm -f "$temp_result"
    echo ""
}

# 检测IP版本
detect_ip_version() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ipv4"
    elif [[ $ip =~ ^[0-9a-fA-F:]+$ ]] && [[ $ip == *":"* ]]; then
        echo "ipv6"
    else
        echo "unknown"
    fi
}

# 解析nexttrace输出，提取AS路径、运营商、地理位置等信息
parse_route_summary() {
    local route_output="$1"
    local used_command="$2"

    # 提取AS号序列
    local as_numbers=$(echo "$route_output" | grep -oE "AS[0-9]+" | awk '!seen[$0]++' | head -6)
    local as_path=""
    if [ -n "$as_numbers" ]; then
        local first=true
        while IFS= read -r as_num; do
            if [ -n "$as_num" ]; then
                if [ "$first" = true ]; then
                    as_path="$as_num"
                    first=false
                else
                    as_path="$as_path > $as_num"
                fi
            fi
        done <<< "$as_numbers"
    fi

    # 提取运营商信息
    local isp_path=""
    local isp_list=""

    # 逐行处理，提取域名或公司名称
    echo "$route_output" | grep "AS[0-9]" | grep -v "RFC1918" | while IFS= read -r line; do
        local isp=""
        # 先尝试提取域名
        isp=$(echo "$line" | grep -oE "[a-zA-Z0-9.-]+\.(com|net|org|io|co)" | tail -1)
        # 没有域名时提取公司名称，但排除常见的误提取
        if [ -z "$isp" ]; then
            local temp_isp=$(echo "$line" | grep -oE "[A-Z][A-Z ]+ [A-Z][A-Z ]*" | tail -1 | sed 's/ SRL$//; s/ LLC$//; s/ INC$//')
            # 只有在行尾才认为是运营商名称，避免误提取
            if echo "$line" | grep -qE "[A-Z][A-Z ]+ [A-Z][A-Z ]*[[:space:]]*$"; then
                isp="$temp_isp"
            fi
        fi
        [ -n "$isp" ] && echo "$isp"
    done | awk '!seen[$0]++' > /tmp/isp_list_$$

    # 构建运营商路径字符串
    if [ -f "/tmp/isp_list_$$" ]; then
        isp_path=$(cat /tmp/isp_list_$$ | paste -sd '>' | sed 's/>/ > /g')
        rm -f /tmp/isp_list_$$
    fi

    # 提取地理位置信息
    local geo_path=""

    # 逐行处理，提取地理位置
    echo "$route_output" | grep "AS[0-9]" | grep -v "RFC1918" | while IFS= read -r line; do
        # 多步骤清理，移除各种干扰信息
        local geo=$(echo "$line" | \
            sed 's/.*AS[0-9]*[[:space:]]*\(\[.*\]\)*[[:space:]]*//' | \
            sed 's/[[:space:]]*[a-zA-Z0-9.-]*\.\(com\|net\|org\|io\|co\).*$//' | \
            sed 's/[[:space:]]*[A-Z][A-Z ]* [A-Z][A-Z ]*.*$//' | \
            sed 's/[[:space:]]*\[.*\][[:space:]]*//' | \
            sed 's/「.*」//g' | \
            sed 's/『.*』//g' | \
            sed "s/'s Backbone.*$//" | \
            sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | \
            sed 's/[[:space:]]\+/ /g' | \
            sed 's/[[:space:]]*$//')

        # 通用过滤：有效地理位置信息
        if [ -n "$geo" ] && [ "$geo" != "*" ] && [ ${#geo} -gt 2 ] && ! echo "$geo" | grep -qE "^[0-9]+$"; then
            # 排除运营商名称和非地理信息
            if ! echo "$geo" | grep -qE "^\[.*\]$|Backbone|backbone|BACKBONE|^[A-Z]+$|^Re[A-Z]+$|^[A-Z][a-z]*[A-Z]+$|Inc\.|LLC|SRL|, Inc"; then
                # 包含非ASCII字符或标准地名格式
                if echo "$geo" | grep -qE "[^\x00-\x7F]|^[A-Z][a-z]+ [A-Z][a-z]+|^[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+"; then
                    echo "$geo"
                fi
            fi
        fi
    done | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/[[:space:]]\+/ /g' | awk '!seen[$0]++' > /tmp/geo_list_$$

    # 构建地理路径字符串
    if [ -f "/tmp/geo_list_$$" ]; then
        geo_path=$(cat /tmp/geo_list_$$ | paste -sd '>' | sed 's/>/ > /g')
        rm -f /tmp/geo_list_$$
    fi

    # 提取地图链接
    local map_url=$(echo "$route_output" | grep -o "https://assets\.nxtrace\.org/tracemap/[^[:space:]]*\.html")

    # 收集路由分析数据
    set_test_result "route_as_path" "$as_path"
    set_test_result "route_isp_path" "$isp_path"
    set_test_result "route_geo_path" "$geo_path"
    set_test_result "route_map_url" "$map_url"

    # 输出总结
    echo -e "${GREEN}📊 路由分析总结 (去程)${NC}"
    echo ""

    [ -n "$used_command" ] && echo -e "${YELLOW}使用指令:${NC} ${used_command}"
    [ -n "$as_path" ] && echo -e "${BLUE}🌐 AS路径:${NC} ${as_path}"
    [ -n "$isp_path" ] && echo -e "${BLUE}🏢 运营商路径:${NC} ${isp_path}"
    [ -n "$geo_path" ] && echo -e "${BLUE}🌍 地理路径:${NC} ${geo_path}"
    [ -n "$map_url" ] && echo -e "${BLUE}🗺️  地图展示:${NC} ${map_url}"
    echo ""
}

# 执行路由分析
run_route_analysis() {
    echo -e "${YELLOW}🟢 路由跟踪分析${NC}"
    echo ""

    # 使用nexttrace进行路由跟踪
    if check_tool "nexttrace"; then
        echo -e "${BLUE}nexttrace 路由分析 - 目标: ${TARGET_IP}:${TARGET_PORT}${NC}"

        # 检测IP版本并构建命令
        local ip_version=$(detect_ip_version "$TARGET_IP")
        local nexttrace_cmd="nexttrace"

        # 添加IP版本参数
        if [ "$ip_version" = "ipv4" ]; then
            nexttrace_cmd="$nexttrace_cmd --ipv4"
        elif [ "$ip_version" = "ipv6" ]; then
            nexttrace_cmd="$nexttrace_cmd --ipv6"
        fi

        # 添加其他优化参数 (使用ICMP模式，更容易通过防火墙)
        nexttrace_cmd="$nexttrace_cmd --route-path --queries 3 --max-hops 25"

        echo ""

        # 执行nexttrace命令
        local route_output=$($nexttrace_cmd "$TARGET_IP" 2>/dev/null)
        local route_exit_code=$?

        if [ $route_exit_code -eq 0 ] && [ -n "$route_output" ]; then
            echo -e "${BLUE}📋 测试数据:${NC}"
            # 过滤掉Route-Path功能实验室部分和MapTrace URL
            echo "$route_output" | sed '/Route-Path 功能实验室/,$d'
            echo ""

            # 解析路由信息
            parse_route_summary "$route_output" "$nexttrace_cmd $TARGET_IP"

            ROUTE_SUCCESS=true
        else
            echo -e "${RED}路由分析失败，尝试基础模式...${NC}"

            # 降级到基础模式
            local basic_output=$(nexttrace "$TARGET_IP" 2>/dev/null)
            local basic_exit_code=$?

            if [ $basic_exit_code -eq 0 ] && [ -n "$basic_output" ]; then
                echo -e "${BLUE}📋 测试数据:${NC}"
                echo "$basic_output"
                echo ""

                # 解析路由信息
                parse_route_summary "$basic_output" "nexttrace $TARGET_IP"

                ROUTE_SUCCESS=true
            else
                echo -e "${RED}❌ 路由分析完全失败${NC}"
                ROUTE_SUCCESS=false
            fi
        fi
    else
        echo -e "${YELLOW}⚠️  nexttrace工具不可用，跳过路由分析${NC}"
        ROUTE_SUCCESS=false
    fi
    echo ""
}



# 全局测试结果变量
FPING_SUCCESS=false
HPING_SUCCESS=false
TCP_SINGLE_SUCCESS=false
TCP_DOWNLOAD_SUCCESS=false
TCP_SUCCESS=false
UDP_SINGLE_SUCCESS=false
UDP_DOWNLOAD_SUCCESS=false
ROUTE_SUCCESS=false

# 主要性能测试函数
run_performance_tests() {
    echo -e "${GREEN}🚀 开始网络性能测试${NC}"
    echo -e "${BLUE}目标: $TARGET_IP:$TARGET_PORT${NC}"
    echo -e "${BLUE}测试时长: ${TEST_DURATION}秒${NC}"
    echo ""

    # 初始化测试结果数据结构
    init_test_results

    # 重置测试结果
    FPING_SUCCESS=false
    HPING_SUCCESS=false
    TCP_SINGLE_SUCCESS=false
    TCP_DOWNLOAD_SUCCESS=false
    TCP_SUCCESS=false
    UDP_SINGLE_SUCCESS=false
    UDP_DOWNLOAD_SUCCESS=false
    ROUTE_SUCCESS=false

    # 执行各项测试
    run_latency_tests
    run_bandwidth_tests
    run_route_analysis

    # 设置TCP总体成功状态
    if [ "$TCP_SINGLE_SUCCESS" = true ] || [ "$TCP_DOWNLOAD_SUCCESS" = true ]; then
        TCP_SUCCESS=true
    fi

    # 生成综合报告
    generate_final_report
}

# 生成最终报告
generate_final_report() {
    echo ""
    echo -e "─────────────────────────────────────────────────────────────────"
    echo -e "${GREEN}🏆 网络性能测试完成${NC}"
    echo ""

    # 报告标题
    echo -e "${BLUE}🌐 网络性能测试报告${NC}"
    echo -e "─────────────────────────────────────────────────────────────────"
    echo -e "  源: 中转机 (本机)"
    echo -e "  目标: $TARGET_IP:$TARGET_PORT"
    echo -e "  测试方向: 中转机 ↔ 落地机 "
    echo -e "  单项测试时长: ${TEST_DURATION}秒"
    echo ""

    # 路由分析结果
    echo -e "${WHITE}🗺️ 路由路径分析${NC}"
    echo -e "─────────────────────────────────────────────────────────────────"

    if [ "$ROUTE_SUCCESS" = true ]; then
        [ -n "${TEST_RESULTS[route_as_path]}" ] && echo -e " AS路径: ${YELLOW}${TEST_RESULTS[route_as_path]}${NC}"
        [ -n "${TEST_RESULTS[route_isp_path]}" ] && echo -e " 运营商: ${YELLOW}${TEST_RESULTS[route_isp_path]}${NC}"
        [ -n "${TEST_RESULTS[route_geo_path]}" ] && echo -e " 地理路径: ${YELLOW}${TEST_RESULTS[route_geo_path]}${NC}"
        [ -n "${TEST_RESULTS[route_map_url]}" ] && echo -e " 地图链接: ${BLUE}${TEST_RESULTS[route_map_url]}${NC}"
    else
        echo -e " ${RED}路由分析失败或数据不可用${NC}"
    fi
    echo ""

    # 核心性能数据展示
    echo -e "    ${WHITE}PING & 抖动${NC}           ${WHITE}⬆️ 上行带宽${NC}           ${WHITE}⬇️ 下行带宽${NC}"
    echo -e "─────────────────────  ─────────────────────  ─────────────────────"

    # 第一行数据
    if [ "$HPING_SUCCESS" = true ] && [ -n "${TEST_RESULTS[latency_avg]}" ]; then
        printf "  平均: ${YELLOW}%-12s${NC}  " "${TEST_RESULTS[latency_avg]}ms"
    else
        printf "  ${RED}%-21s${NC}  " "测试失败"
    fi

    if [ "$TCP_SINGLE_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_up_speed_mbps]}" ]; then
        printf "  ${YELLOW}%s Mbps${NC} (${YELLOW}%s MiB/s${NC})  " "${TEST_RESULTS[tcp_up_speed_mbps]}" "${TEST_RESULTS[tcp_up_speed_mibs]}"
    else
        printf "  ${RED}%-21s${NC}  " "测试失败"
    fi

    if [ "$TCP_DOWNLOAD_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_down_speed_mbps]}" ]; then
        printf "  ${YELLOW}%s Mbps${NC} (${YELLOW}%s MiB/s${NC})\n" "${TEST_RESULTS[tcp_down_speed_mbps]}" "${TEST_RESULTS[tcp_down_speed_mibs]}"
    else
        printf "  ${RED}%-21s${NC}\n" "测试失败"
    fi

    # 第二行数据
    if [ "$HPING_SUCCESS" = true ] && [ -n "${TEST_RESULTS[latency_min]}" ]; then
        printf "  最低: ${YELLOW}%-12s${NC}  " "${TEST_RESULTS[latency_min]}ms"
    else
        printf "  %-21s  " ""
    fi

    if [ "$TCP_SINGLE_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_up_transfer]}" ]; then
        printf "  总传输量: ${YELLOW}%-11s${NC}  " "${TEST_RESULTS[tcp_up_transfer]} MB"
    else
        printf "  %-21s  " ""
    fi

    if [ "$TCP_DOWNLOAD_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_down_transfer]}" ]; then
        printf "  总传输量: ${YELLOW}%-11s${NC}\n" "${TEST_RESULTS[tcp_down_transfer]} MB"
    else
        printf "  %-21s\n" ""
    fi

    # 第三行数据
    if [ "$HPING_SUCCESS" = true ] && [ -n "${TEST_RESULTS[latency_max]}" ]; then
        printf "  最高: ${YELLOW}%-12s${NC}  " "${TEST_RESULTS[latency_max]}ms"
    else
        printf "  %-21s  " ""
    fi

    if [ "$TCP_SINGLE_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_up_retrans]}" ]; then
        printf "  重传: ${YELLOW}%-15s${NC}  " "${TEST_RESULTS[tcp_up_retrans]} 次"
    else
        printf "  %-21s  " ""
    fi

    if [ "$TCP_DOWNLOAD_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_down_retrans]}" ]; then
        printf "  重传: ${YELLOW}%-15s${NC}\n" "${TEST_RESULTS[tcp_down_retrans]} 次"
    else
        printf "  %-21s\n" ""
    fi

    # 第四行数据
    if [ "$HPING_SUCCESS" = true ] && [ -n "${TEST_RESULTS[latency_jitter]}" ]; then
        printf "  抖动: ${YELLOW}%-12s${NC}  " "${TEST_RESULTS[latency_jitter]}ms"
    else
        printf "  %-21s  " ""
    fi

    if [ "$TCP_SINGLE_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_up_congestion]}" ]; then
        # 格式化拥塞控制算法显示
        local up_congestion_short=$(echo "${TEST_RESULTS[tcp_up_congestion]}" | sed 's/(发) /发/; s/ > (收) / \/ 收/')
        printf "  拥塞: ${YELLOW}%-15s${NC}  " "$up_congestion_short"
    else
        printf "  %-21s  " ""
    fi

    # TCP下行拥塞控制算法
    if [ "$TCP_DOWNLOAD_SUCCESS" = true ] && [ -n "${TEST_RESULTS[tcp_down_congestion]}" ]; then
        local down_congestion_short=$(echo "${TEST_RESULTS[tcp_down_congestion]}" | sed 's/(发) /发/; s/ > (收) / \/ 收/')
        printf "  拥塞: ${YELLOW}%-15s${NC}\n" "$down_congestion_short"
    else
        printf "  %-21s\n" ""
    fi
    echo ""

    # UDP协议性能详情
    echo -e "${WHITE}UDP 协议性能详情${NC}"
    echo -e "─────────────────────────────────────────────────────────────────"
    echo -e " 方向     │ 吞吐量        │ 丢包率        │ 抖动"
    echo -e "─────────────────────────────────────────────────────────────────"

    # UDP上行
    if [ "$UDP_SINGLE_SUCCESS" = true ] && [ -n "${TEST_RESULTS[udp_up_speed_mbps]}" ]; then
        printf " ⬆️ 上行   │ ${YELLOW}%-12s${NC} │ ${YELLOW}%-12s${NC} │ ${YELLOW}%-12s${NC}\n" \
            "${TEST_RESULTS[udp_up_speed_mbps]} Mbps" \
            "${TEST_RESULTS[udp_up_loss]}" \
            "${TEST_RESULTS[udp_up_jitter]} ms"
    else
        printf " ⬆️ 上行   │ ${RED}%-12s${NC} │ ${RED}%-12s${NC} │ ${RED}%-12s${NC}\n" \
            "测试失败" "N/A" "N/A"
    fi

    # UDP下行
    if [ "$UDP_DOWNLOAD_SUCCESS" = true ] && [ -n "${TEST_RESULTS[udp_down_speed_mbps]}" ]; then
        printf " ⬇️ 下行   │ ${YELLOW}%-12s${NC} │ ${YELLOW}%-12s${NC} │ ${YELLOW}%-12s${NC}\n" \
            "${TEST_RESULTS[udp_down_speed_mbps]} Mbps" \
            "${TEST_RESULTS[udp_down_loss]}" \
            "${TEST_RESULTS[udp_down_jitter]} ms"
    else
        printf " ⬇️ 下行   │ ${RED}%-12s${NC} │ ${RED}%-12s${NC} │ ${RED}%-12s${NC}\n" \
            "测试失败" "N/A" "N/A"
    fi

    echo ""
    echo -e "─────────────────────────────────────────────────────────────────"
    echo -e "测试完成时间: $(TZ='Asia/Shanghai' date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo -e "${WHITE}按任意键返回主菜单...${NC}"
    read -n 1 -s
}

# 中转机模式 - 发起测试
relay_server_mode() {
    clear
    echo -e "${GREEN}=== 中转机模式 ===${NC}"
    echo ""

    # 输入落地机IP (目标服务器)
    while true; do
        read -p "落地机IP (目标服务器): " TARGET_IP

        if [ -z "$TARGET_IP" ]; then
            echo -e "${RED}请输入落地机的IP地址${NC}"
        elif validate_ip "$TARGET_IP"; then
            break
        else
            echo -e "${RED}无效的IP地址或域名格式${NC}"
        fi
    done

    # 输入测试端口
    while true; do
        read -p "测试端口 [默认5201]: " input_port
        if [ -z "$input_port" ]; then
            TARGET_PORT="5201"
            break
        elif validate_port "$input_port"; then
            TARGET_PORT="$input_port"
            break
        else
            echo -e "${RED}无效端口号，请输入1-65535之间的数字${NC}"
        fi
    done

    # 输入测试时长
    while true; do
        read -p "测试时长(秒) [默认30]: " input_duration
        if [ -z "$input_duration" ]; then
            TEST_DURATION="30"
            break
        elif [[ $input_duration =~ ^[0-9]+$ ]] && [ "$input_duration" -ge 5 ] && [ "$input_duration" -le 300 ]; then
            TEST_DURATION="$input_duration"
            break
        else
            echo -e "${RED}测试时长必须是5-300秒之间的数字${NC}"
        fi
    done

    echo ""
    echo -e "${YELLOW}连接检查...${NC}"

    # 测试连通性
    if test_connectivity "$TARGET_IP" "$TARGET_PORT"; then
        echo -e "${GREEN}✅ 连接正常，开始测试${NC}"
        echo ""

        # 开始性能测试
        run_performance_tests
    else
        echo -e "${RED}✗ 无法连接到 $TARGET_IP:$TARGET_PORT${NC}"
        echo -e "${YELLOW}请确认：${NC}"
        echo -e "${YELLOW}1. 落地机已启动iperf3服务${NC}"
        echo -e "${YELLOW}2. IP地址和端口正确${NC}"
        echo -e "${YELLOW}3. 防火墙已放行端口${NC}"
        echo ""
        echo -e "${WHITE}按任意键返回主菜单...${NC}"
        read -n 1 -s
    fi
}

# 卸载单个APT工具
uninstall_apt_tool() {
    local tool="$1"
    local package="$2"

    if apt-get remove -y "$package" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $tool 卸载成功${NC}"
        TOOL_STATUS["$tool"]="missing"
        return 0
    else
        echo -e "${RED}✗ $tool 卸载失败${NC}"
        return 1
    fi
}

# 卸载自定义工具
uninstall_custom_tool() {
    local tool="$1"

    case "$tool" in
        "nexttrace")
            if [ -f "/usr/local/bin/nexttrace" ]; then
                rm -f "/usr/local/bin/nexttrace"
                echo -e "${GREEN}✅ nexttrace 卸载成功${NC}"
                TOOL_STATUS["nexttrace"]="missing"
                return 0
            else
                echo -e "${YELLOW}⚠️  nexttrace 未安装${NC}"
                return 0
            fi
            ;;
        *)
            echo -e "${RED}✗ 未知的自定义工具: $tool${NC}"
            return 1
            ;;
    esac
}

# 清理进程和临时文件
cleanup_system() {
    echo -e "${BLUE}停止相关进程...${NC}"
    pkill -f "iperf3.*-s" 2>/dev/null
    pkill -f "hping3\|nexttrace\|fping" 2>/dev/null

    echo -e "${BLUE}清理临时文件...${NC}"
    rm -f /tmp/isp_list_* /tmp/geo_list_* "$INITIAL_STATUS_FILE" 2>/dev/null
    find /tmp -name "tmp.*" -user "$(whoami)" -mtime +0 -delete 2>/dev/null || true
}

# 检测脚本位置
get_script_paths() {
    local paths=("$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local common_paths=("/usr/local/bin/speedtest.sh" "/etc/realm/speedtest.sh" "./speedtest.sh")

    for path in "${common_paths[@]}"; do
        [ -f "$path" ] && paths+=("$path")
    done

    printf '%s\n' "${paths[@]}" | sort -u
}

# 卸载新安装的工具
uninstall_tools() {
    local tools=($(get_newly_installed_tools))
    [ ${#tools[@]} -eq 0 ] && return 0

    for tool in "${tools[@]}"; do
        local config="${REQUIRED_TOOLS[$tool]}"
        local type="${config%%:*}"
        local package="${config##*:}"

        case "$type" in
            "apt") uninstall_apt_tool "$tool" "$package" ;;
            "custom") uninstall_custom_tool "$tool" ;;
        esac
    done

    apt-get autoremove -y >/dev/null 2>&1
    apt-get autoclean >/dev/null 2>&1
}

# 卸载脚本
uninstall_speedtest() {
    clear
    echo -e "${RED}=== 卸载测速测试工具 ===${NC}"
    echo ""

    detect_all_tools
    local tools=($(get_newly_installed_tools))
    local scripts=($(get_script_paths))

    echo -e "${YELLOW}将执行以下操作：${NC}"
    if [ ${#tools[@]} -gt 0 ]; then
        echo -e "${BLUE}• 卸载工具: ${tools[*]}${NC}"
    else
        echo -e "${YELLOW}• 无需卸载工具${NC}"
    fi
    echo -e "${BLUE}• 删除脚本文件${NC}"
    echo -e "${BLUE}• 清理临时文件和进程${NC}"
    echo -e "${GREEN}• 恢复到未使用过本功能的状态${NC}"
    echo ""

    read -p "确认卸载？(y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # 卸载工具
        if [ ${#tools[@]} -gt 0 ]; then
            echo -e "${YELLOW}卸载工具...${NC}"
            uninstall_tools
        fi

        # 清理系统
        cleanup_system

        # 删除脚本文件
        echo -e "${BLUE}删除脚本文件...${NC}"
        local deleted_count=0
        while IFS= read -r script_path; do
            if [ -f "$script_path" ]; then
                rm -f "$script_path"
                echo -e "${GREEN}✅ 删除 $script_path${NC}"
                ((deleted_count++))
            fi
        done < <(get_script_paths)

        if [ $deleted_count -eq 0 ]; then
            echo -e "${YELLOW}未找到脚本文件${NC}"
        fi

        echo ""
        echo -e "${GREEN}⌛ 已恢复到未使用过本功能的状态${NC}"
        echo -e "${WHITE}按任意键退出...${NC}"
        read -n 1 -s
        exit 0
    else
        show_main_menu
    fi
}

# 主菜单
show_main_menu() {
    clear
    echo -e "${GREEN}=== 网络链路测试(先开放,再发起) ===${NC}"
    echo ""
    echo "请选择操作:"
    echo -e "${GREEN}1.${NC} 中转机 (发起测试)"
    echo -e "${BLUE}2.${NC} 落地机 (开放测试)"
    echo -e "${RED}3.${NC} 卸载脚本"
    echo -e "${YELLOW}4.${NC} 返回中转脚本"
    echo ""

    while true; do
        read -p "请输入选择 [1-4]: " choice
        case $choice in
            1)
                ROLE="relay"
                relay_server_mode
                show_main_menu
                ;;
            2)
                ROLE="landing"
                landing_server_mode
                show_main_menu
                ;;
            3)
                uninstall_speedtest
                ;;
            4)
                echo -e "${BLUE}返回中转脚本主菜单...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-4${NC}"
                ;;
        esac
    done
}

# 主函数
main() {
    check_root

    # 检测工具状态并安装缺失的工具
    install_required_tools

    # 显示主菜单
    show_main_menu
}

# 执行主函数
main "$@"