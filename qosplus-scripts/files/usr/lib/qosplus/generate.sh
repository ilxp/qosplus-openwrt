#!/bin/sh
# 检查是否存在 /lib/functions.sh 文件，如果存在则加载，否则加载当前目录下的 functions.sh
[ -e /lib/functions.sh ] && . /lib/functions.sh || . ./functions.sh
# 检查 /sbin/modprobe 是否可执行，如果可执行则设置 insmod 为 modprobe，否则设置为 insmod
[ -x /sbin/modprobe ] && {
	insmod="modprobe"
} || {
	insmod="insmod"
}
# 设置 rmmod 变量为 rmmod
rmmod="rmmod"

# 定义 add_insmod 函数，用于添加内核模块
add_insmod() {
	# 评估 insmod_变量的值
	eval "export isset=\${insmod_$1}"
	# 根据 isset 的值进行处理
	case "$isset" in
		1) ;;  # 如果 isset 为 1，则不进行任何操作
		*) {  # 如果 isset 不为 1，则执行以下操作
			# 如果第二个参数存在，则将卸载模块的命令追加到 INSMOD 变量中
			[ "$2" ] && append INSMOD "$rmmod $1 >&- 2>&-" "$N"
			# 将加载模块的命令追加到 INSMOD 变量中，并设置 insmod_变量为 1
			append INSMOD "$insmod $* >&- 2>&-" "$N"; export insmod_$1=1
		};;
	esac
}

# 检查 /etc/config/network 文件是否存在
[ -e /etc/config/network ] && {
	# 仅在 OpenWrt 上尝试解析网络配置
	. /lib/functions/network.sh

	# 定义 find_ifname 函数，用于查找接口名称
	find_ifname() {
		local ifname
		# 如果 network_get_device 函数能够获取到接口名称，则返回该名称
		if network_get_device ifname "$1"; then
			echo "$ifname"
		else
			# 如果无法找到接口名称，则输出错误信息并退出
			echo "Device for interface $1 not found." >&2
			exit 1
		fi
	}
} || {
	# 如果 /etc/config/network 文件不存在，则定义一个简单的 find_ifname 函数
	find_ifname() {
		# 输出错误信息并退出
		echo "Interface not found." >&2
		exit 1
	}
}

# 定义 parse_matching_rule 函数，用于解析匹配规则
parse_matching_rule() {
	local var="$1"
	local section="$2"
	local options="$3"
	local prefix="$4"
	local suffix="$5"
	local proto="$6"
	local mport=""
	local ports=""

	# 将前缀追加到 var 变量中
	append "$var" "$prefix" "$N"
	# 遍历选项
	for option in $options; do
		# 根据选项类型设置 proto 变量
		case "$option" in
			proto) config_get value "$section" proto; proto="${proto:-$value}";;
		esac
	done
	# 获取类型
	config_get type "$section" TYPE
	# 根据类型设置 pkt 变量和追加匹配规则
	case "$type" in
		classify) unset pkt; append "$var" "-m mark --mark 0/0x0f";;
		default) pkt=1; append "$var" "-m mark --mark 0/0xf0";;
		reclassify) pkt=1;;
	esac
	# 追加协议匹配规则
	append "$var" "${proto:+-p $proto}"
	# 再次遍历选项，根据不同的选项追加不同的匹配规则
	for option in $options; do
		config_get value "$section" "$option"

		case "$pkt:$option" in
			*:srchost)
				append "$var" "-s $value"
			;;
			*:dsthost)
				append "$var" "-d $value"
			;;
			*:ports|*:srcports|*:dstports)
				value="$(echo "$value" | sed -e 's,-,:,g')"
				lproto=${lproto:-tcp}
				case "$proto" in
					""|tcp|udp) append "$var" "-m ${proto:-tcp -p tcp} -m multiport";;
					*) unset "$var"; return 0;;
				esac
				case "$option" in
					ports)
						config_set "$section" srcports ""
						config_set "$section" dstports ""
						config_set "$section" portrange ""
						append "$var" "--ports $value"
					;;
					srcports)
						config_set "$section" ports ""
						config_set "$section" dstports ""
						config_set "$section" portrange ""
						append "$var" "--sports $value"
					;;
					dstports)
						config_set "$section" ports ""
						config_set "$section" srcports ""
						config_set "$section" portrange ""
						append "$var" "--dports $value"
					;;
				esac
				ports=1
			;;
			*:portrange)
				config_set "$section" ports ""
				config_set "$section" srcports ""
				config_set "$section" dstports ""
				value="$(echo "$value" | sed -e 's,-,:,g')"
				case "$proto" in
					""|tcp|udp) append "$var" "-m ${proto:-tcp -p tcp} --sport $value --dport $value";;
					*) unset "$var"; return 0;;
				esac
				ports=1
			;;
			*:connbytes)
				value="$(echo "$value" | sed -e 's,-,:,g')"
				add_insmod xt_connbytes
				append "$var" "-m connbytes --connbytes $value --connbytes-dir both --connbytes-mode bytes"
			;;
			*:comment)
				add_insmod xt_comment
				append "$var" "-m comment --comment '$value'"
			;;
			*:tos)
				add_insmod xt_dscp
				case "$value" in
					!*) append "$var" "-m tos ! --tos $value";;
					*) append "$var" "-m tos --tos $value"
				esac
			;;
			*:dscp)
				add_insmod xt_dscp
				dscp_option="--dscp"
				[ -z "${value%%[EBCA]*}" ] && dscp_option="--dscp-class"
				case "$value" in
					!*) append "$var" "-m dscp ! $dscp_option $value";;
					*) append "$var" "-m dscp $dscp_option $value"
				esac
			;;
			*:direction)
				value="$(echo "$value" | sed -e 's,-,:,g')"
				if [ "$value" = "out" ]; then
					append "$var" "-o $device"
				elif [ "$value" = "in" ]; then
					append "$var" "-i $device"
				fi
			;;
			*:srciface)
				append "$var" "-i $value"
			;;
			1:pktsize)
				value="$(echo "$value" | sed -e 's,-,:,g')"
				add_insmod xt_length
				append "$var" "-m length --length $value"
			;;
			1:limit)
				add_insmod xt_limit
				append "$var" "-m limit --limit $value"
			;;
			1:tcpflags)
				case "$proto" in
					tcp) append "$var" "-m tcp --tcp-flags ALL $value";;
					*) unset $var; return 0;;
				esac
			;;
			1:mark)
				config_get class "${value##!}" classnr
				[ -z "$class" ] && continue;
				case "$value" in
					!*) append "$var" "-m mark ! --mark $class/0x0f";;
					*) append "$var" "-m mark --mark $class/0x0f";;
				esac
			;;
			1:TOS)
				add_insmod xt_DSCP
				config_get TOS "$rule" 'TOS'
				suffix="-j TOS --set-tos "${TOS:-"Normal-Service"}
			;;
			1:DSCP)
				add_insmod xt_DSCP
				config_get DSCP "$rule" 'DSCP'
				[ -z "${DSCP%%[EBCA]*}" ] && set_value="--set-dscp-class $DSCP" \
				|| set_value="--set-dscp $DSCP"
				suffix="-j DSCP $set_value"
			;;
		esac
	done
	# 追加后缀
	append "$var" "$suffix"
	# 根据端口和协议再次调用 parse_matching_rule 函数
	case "$ports:$proto" in
		1:)	parse_matching_rule "$var" "$section" "$options" "$prefix" "$suffix" "udp";;
	esac
}

# 定义 config_cb 函数，用于处理配置回调
config_cb() {
	option_cb() {
		return 0
	}
	# 根据不同的配置类型进行处理
	case "$1" in
		interface)
			# 设置接口的默认类组和上传带宽
			config_set "$2" "classgroup" "Default"
			config_set "$2" "upload" "128"
		;;
		classify|default|reclassify)
			# 定义 option_cb 函数，用于追加配置选项
			option_cb() {
				append "CONFIG_${CONFIG_SECTION}_options" "$1"
			}
		;;
	esac
}

# 定义 qos_parse_config 函数，用于解析 QoS 配置
qos_parse_config() {
	config_get TYPE "$1" TYPE
	# 根据配置类型进行处理
	case "$TYPE" in
		interface)
			# 获取接口的启用状态和类组
			config_get_bool enabled "$1" enabled 1
			[ 1 -eq "$enabled" ] && {
				config_get classgroup "$1" classgroup
				config_set "$1" ifbdev "$C"
				C=$(($C+1))
				append INTERFACES "$1"
				config_set "$classgroup" enabled 1
				config_get device "$1" device
				# 如果设备未设置，则尝试查找设备名称
				[ -z "$device" ] && {
					device="$(find_ifname $1)"
					# 如果找不到设备名称，则退出
					[ -z "$device" ] && exit 1
					config_set "$1" device "$device"
				}
			}
		;;
		classgroup) append CG "$1";;
		classify|default|reclassify)
			# 根据类型设置变量
			case "$TYPE" in
				classify) var="ctrules";;
				*) var="rules";;
			esac
			# 将配置项追加到相应的变量中
			append "$var" "$1"
		;;
	esac
}

# 定义 enum_classes 函数，用于枚举类
enum_classes() {
	local c="0"
	config_get classes "$1" classes
	config_get default "$1" default
	# 遍历类并设置类编号
	for class in $classes; do
		c="$(($c + 1))"
		config_set "${class}" classnr $c
		# 设置默认类
		case "$class" in
			$default) class_default=$c;;
		esac
	done
	class_default="${class_default:-$c}"
}

# 定义 cls_var 函数，用于设置类变量
cls_var() {
	local varname="$1"
	local class="$2"
	local name="$3"
	local type="$4"
	local default="$5"
	local tmp tmp1 tmp2
	# 获取类变量值
	config_get tmp1 "$class" "$name"
	config_get tmp2 "${class}_${type}" "$name"
	tmp="${tmp2:-$tmp1}"
	tmp="${tmp:-$tmp2}"
	# 导出变量
	export ${varname}="${tmp:-$default}"
}

# 定义 tcrules 函数，用于生成流量控制规则
tcrules() {
	_dir=/usr/lib/qosplus
	# 如果 tcrules.awk 文件不存在，则设置默认目录
	[ -e $_dir/tcrules.awk ] || _dir=.
	# 使用 awk 生成规则
	echo "$cstr" | awk \
		-v device="$dev" \
		-v linespeed="$rate" \
		-v direction="$dir" \
		-f $_dir/tcrules.awk
}

# 定义 start_interface 函数，用于启动接口
start_interface() {
	local iface="$1"
	local num_ifb="$2"
	config_get device "$iface" device
	config_get_bool enabled "$iface" enabled 1
	# 如果设备未设置或未启用，则返回
	[ -z "$device" -o 1 -ne "$enabled" ] && {
		return 1
	}
	config_get upload "$iface" upload
	config_get_bool halfduplex "$iface" halfduplex
	config_get download "$iface" download
	config_get classgroup "$iface" classgroup
	config_get_bool overhead "$iface" overhead 0

	download="${download:-${halfduplex:+$upload}}"
	enum_classes "$classgroup"
	# 根据方向设置变量
	for dir in ${halfduplex:-up} ${download:+down}; do
		case "$dir" in
			up)
				# 设置上行方向的变量
				[ "$overhead" = 1 ] && upload=$(($upload * 98 / 100 - (15 * 128 / $upload)))
				dev="$device"
				rate="$upload"
				dl_mode=""
				prefix="cls"
			;;
			down)
				# 设置下行方向的变量
				[ "$(ls -d /proc/sys/net/ipv4/conf/ifb* 2>&- | wc -l)" -ne "$num_ifb" ] && add_insmod ifb numifbs="$num_ifb"
				config_get ifbdev "$iface" ifbdev
				[ "$overhead" = 1 ] && download=$(($download * 98 / 100 - (80 * 1024 / $download)))
				dev="ifb$ifbdev"
				rate="$download"
				dl_mode=1
				prefix="d_cls"
			;;
			*) continue;;
		esac
		cstr=
		# 遍历类并设置类变量
		for class in $classes; do
			cls_var pktsize "$class" packetsize $dir 1500
			cls_var pktdelay "$class" packetdelay $dir 0
			cls_var maxrate "$class" limitrate $dir 100
			cls_var prio "$class" priority $dir 1
			cls_var avgrate "$class" avgrate $dir 0
			cls_var qdisc "$class" qdisc $dir ""
			cls_var filter "$class" filter $dir ""
			config_get classnr "$class" classnr
			# 追加类字符串
			append cstr "$classnr:$prio:$avgrate:$pktsize:$pktdelay:$maxrate:$qdisc:$filter" "$N"
		done
		# 追加方向队列规则
		append ${prefix}q "$(tcrules)" "$N"
		# 导出设备设置命令
		export dev_${dir}="ip link add ${dev} type ifb >&- 2>&-
ip link set $dev up >&- 2>&-
tc qdisc del dev $dev root >&- 2>&-
tc qdisc add dev $dev root handle 1: hfsc default ${class_default}0
tc class add dev $dev parent 1: classid 1:1 hfsc sc rate ${rate}kbit ul rate ${rate}kbit"
	done
	# 如果存在下载方向，则加载相应的内核模块
	[ -n "$download" ] && {
		add_insmod cls_u32
		add_insmod em_u32
		add_insmod act_connmark
		add_insmod act_mirred
		add_insmod sch_ingress
	}
	# 如果存在半双工模式，则设置上行队列规则
	if [ -n "$halfduplex" ]; then
		export dev_up="tc qdisc del dev $device root >&- 2>&-
tc qdisc add dev $device root handle 1: hfsc
tc filter add dev $device parent 1: prio 10 u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb$ifbdev"
	# 如果存在下载方向，则设置下行队列规则
	elif [ -n "$download" ]; then
		append dev_${dir} "tc qdisc del dev $device ingress >&- 2>&-
tc qdisc add dev $device ingress
tc filter add dev $device parent ffff: prio 1 u32 match u32 0 0 flowid 1:1 action connmark action mirred egress redirect dev ifb$ifbdev" "$N"
	fi
	# 加载防火墙模块
	add_insmod cls_fw
	add_insmod sch_hfsc

	# 输出设备设置命令
	cat <<EOF
${INSMOD:+$INSMOD$N}${dev_up:+$dev_up
$clsq
}${ifbdev:+$dev_down
$d_clsq
$d_clsl
$d_clsf
}
EOF
	# 清除变量
	unset INSMOD clsq clsf clsl d_clsq d_clsl d_clsf dev_up dev_down
}

# 定义 start_interfaces 函数，用于启动所有接口
start_interfaces() {
	local C="$1"
	# 遍历接口并启动
	for iface in $INTERFACES; do
		start_interface "$iface" "$C"
	done
}

# 定义 add_rules 函数，用于添加规则
add_rules() {
	local var="$1"
	local rules="$2"
	local prefix="$3"

	# 遍历规则并添加
	for rule in $rules; do
		unset iptrule
		config_get target "$rule" target
		config_get target "$target" classnr
		config_get options "$rule" options

		# 如果需要覆盖 TOS 字段，则清除 DSCP 字段
		[ ! -z "$(echo $options | grep 'TOS')" ] && {
			s_options=${options%%TOS}
			add_insmod xt_DSCP
			parse_matching_rule iptrule "$rule" "$s_options" "$prefix" "-j DSCP --set-dscp 0"
			append "$var" "$iptrule" "$N"
			unset iptrule
		}

		# 设置目标和解析匹配规则
		target=$(($target | ($target << 4)))
		parse_matching_rule iptrule "$rule" "$options" "$prefix" "-j MARK --set-mark $target/0xff"
		append "$var" "$iptrule" "$N"
	done
}

# 定义 start_cg 函数，用于启动类组
start_cg() {
	local cg="$1"
	local iptrules
	local pktrules
	local sizerules
	enum_classes "$cg"
	# 遍历命令并添加规则
	for command in $iptables; do
		add_rules iptrules "$ctrules" "$command -w -t mangle -A qos_${cg}_ct"
	done
	config_get classes "$cg" classes
	# 遍历类并添加规则
	for class in $classes; do
		config_get mark "$class" classnr
		config_get maxsize "$class" maxsize
		# 如果类设置了最大大小和标记，则添加规则
		[ -z "$maxsize" -o -z "$mark" ] || {
			add_insmod xt_length
			for command in $iptables; do
				append pktrules "$command -w -t mangle -A qos_${cg} -m mark --mark $mark/0x0f -m length --length $maxsize: -j MARK --set-mark 0/0xff" "$N"
			done
		}
	done
	# 遍历命令并添加规则
	for command in $iptables; do
		add_rules pktrules "$rules" "$command -w -t mangle -A qos_${cg}"
	done
	# 遍历接口并添加规则
	for iface in $INTERFACES; do
		config_get classgroup "$iface" classgroup
		config_get device "$iface" device
		config_get ifbdev "$iface" ifbdev
		config_get upload "$iface" upload
		config_get download "$iface" download
		config_get halfduplex "$iface" halfduplex
		download="${download:-${halfduplex:+$upload}}"
		# 遍历命令并添加规则
		for command in $iptables; do
			append up "$command -w -t mangle -A OUTPUT -o $device -j qos_${cg}" "$N"
			append up "$command -w -t mangle -A FORWARD -o $device -j qos_${cg}" "$N"
		done
	done
	# 输出模块加载命令
	cat <<EOF
$INSMOD
EOF

	# 输出链创建命令
	for command in $iptables; do
		cat <<EOF
	$command -w -t mangle -N qos_${cg}
	$command -w -t mangle -N qos_${cg}_ct
EOF
	done
	# 输出匹配规则
	cat <<EOF
	${iptrules:+${iptrules}${N}}
EOF
	for command in $iptables; do
		cat <<EOF
	$command -w -t mangle -A qos_${cg}_ct -j CONNMARK --save-mark --mask 0xff
	$command -w -t mangle -A qos_${cg} -j CONNMARK --restore-mark --mask 0x0f
	$command -w -t mangle -A qos_${cg} -m mark --mark 0/0x0f -j qos_${cg}_ct
EOF
	done
	# 输出包规则
	cat <<EOF
$pktrules
EOF
	# 输出连接保存命令
	for command in $iptables; do
		cat <<EOF
	$command -w -t mangle -A qos_${cg} -j CONNMARK --save-mark --mask 0xff
EOF
	done
	# 输出上行和下行规则
	cat <<EOF
$up$N${down:+${down}$N}
EOF
	# 清除变量
	unset INSMOD
}

# 定义 start_firewall 函数，用于启动防火墙
start_firewall() {
	add_insmod xt_multiport
	add_insmod xt_connmark
	stop_firewall
	# 遍历类组并启动
	for group in $CG; do
		start_cg $group
	done
}

# 定义 stop_firewall 函数，用于停止防火墙
stop_firewall() {
	# 构建清除防火墙规则的命令列表
	for command in $iptables; do
		$command -w -t mangle -S |
			# 查找防火墙链规则
			grep -E '(^-N qos_|-j qos_)' |
			# 排除防火墙链内部引用
			grep -v '^-A qos_' |
			# 替换命令
			sed -e '/^-N/{s/^-N/-X/;H;s/^-X/-F/}' \
				-e 's/^-A/-D/' \
				-e '${p;g}' |
			# 转换为正确的 iptables 命令
			sed -n -e "s/^./${command} -w -t mangle &/p"
	done
}

# 初始化变量
C="0"
INTERFACES=""
# 如果存在 qosplus.conf 文件，则加载配置
[ -e ./qosplus.conf ] && {
	. ./qosplus.conf
	config_cb
} || {
	# 否则加载 qos 配置
	config_load qosplus
	config_foreach qos_parse_config
}

# 初始化接口计数
C="0"
# 遍历接口并设置计数
for iface in $INTERFACES; do
	export C="$(($C + 1))"
done

# 检查是否安装了 ip6tables
[ -x /usr/sbin/ip6tables ] && {
	iptables="ip6tables iptables"
} || {
	iptables="iptables"
}

# 根据参数执行不同的操作
case "$1" in
	all)
		# 启动所有接口和防火墙
		start_interfaces "$C"
		start_firewall
	;;
	interface)
		# 启动指定接口
		start_interface "$2" "$C"
	;;
	interfaces)
		# 启动所有接口
		start_interfaces
	;;
	firewall)
		# 根据参数启动或停止防火墙
		case "$2" in
			stop)
				stop_firewall
			;;
			start|"")
				start_firewall
			;;
		esac
	;;
esac