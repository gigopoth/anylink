package dbdata

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/songgao/water/waterutil"
)

func GetPolicy(Username string) *Policy {
	policyData := &Policy{}
	err := One("Username", Username, policyData)
	if err != nil {
		return policyData
	}
	return policyData
}

func SetPolicy(p *Policy) error {
	var err error
	if p.Username == "" {
		return errors.New("用户名错误")
	}

	// 包含路由
	routeInclude := []ValData{}
	for _, v := range p.RouteInclude {
		if v.Val != "" {
			if v.Val == ALL {
				routeInclude = append(routeInclude, v)
				continue
			}

			ipMask, ipNet, err := parseIpNet(v.Val)
			if err != nil {
				return errors.New("RouteInclude 错误" + err.Error())
			}

			if strings.Split(ipMask, "/")[0] != ipNet.IP.String() {
				errMsg := fmt.Sprintf("RouteInclude 错误: 网络地址错误，建议： %s 改为 %s", v.Val, ipNet)
				return errors.New(errMsg)
			}

			v.IpMask = ipMask
			routeInclude = append(routeInclude, v)
		}
	}
	p.RouteInclude = routeInclude
	// 排除路由
	routeExclude := []ValData{}
	for _, v := range p.RouteExclude {
		if v.Val != "" {
			ipMask, ipNet, err := parseIpNet(v.Val)
			if err != nil {
				return errors.New("RouteExclude 错误" + err.Error())
			}

			if strings.Split(ipMask, "/")[0] != ipNet.IP.String() {
				errMsg := fmt.Sprintf("RouteInclude 错误: 网络地址错误，建议： %s 改为 %s", v.Val, ipNet)
				return errors.New(errMsg)
			}
			v.IpMask = ipMask
			routeExclude = append(routeExclude, v)
		}
	}
	p.RouteExclude = routeExclude

	// DNS 判断
	clientDns := []ValData{}
	for _, v := range p.ClientDns {
		if v.Val != "" {
			ip := net.ParseIP(v.Val)
			if ip.String() != v.Val {
				return errors.New("DNS IP 错误")
			}
			clientDns = append(clientDns, v)
		}
	}
	if len(routeInclude) == 0 || (len(routeInclude) == 1 && routeInclude[0].Val == "all") {
		if len(clientDns) == 0 {
			return errors.New("默认路由，必须设置一个DNS")
		}
	}
	p.ClientDns = clientDns

	// 域名拆分隧道，不能同时填写
	p.DsIncludeDomains = strings.TrimSpace(p.DsIncludeDomains)
	p.DsExcludeDomains = strings.TrimSpace(p.DsExcludeDomains)
	if p.DsIncludeDomains != "" && p.DsExcludeDomains != "" {
		return errors.New("包含/排除域名不能同时填写")
	}
	// 校验包含域名的格式
	err = CheckDomainNames(p.DsIncludeDomains)
	if err != nil {
		return errors.New("包含域名有误：" + err.Error())
	}
	// 校验排除域名的格式
	err = CheckDomainNames(p.DsExcludeDomains)
	if err != nil {
		return errors.New("排除域名有误：" + err.Error())
	}

	// 转换ACL数据
	linkAcl := []GroupLinkAcl{}
	for _, v := range p.LinkAcl {
		if v.Val != "" {
			_, ipNet, err := parseIpNet(v.Val)
			if err != nil {
				return errors.New("LinkAcl 错误" + err.Error())
			}
			v.IpNet = ipNet

			// 设置协议数据
			switch v.Protocol {
			case ALL, "":
				v.Protocol = ALL
			case TCP:
				v.IpProto = waterutil.TCP
			case UDP:
				v.IpProto = waterutil.UDP
			case ICMP:
				v.IpProto = waterutil.ICMP
			default:
				return fmt.Errorf("LinkAcl 错误: 不支持的协议类型 '%s', 仅支持 all/tcp/udp/icmp", v.Protocol)
			}

			portsStr := v.Port
			v.Port = strings.TrimSpace(portsStr)

			if regexp.MustCompile(`^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$`).MatchString(portsStr) {
				ports := map[uint16]int8{}
				for _, p := range strings.Split(portsStr, ",") {
					if p == "" {
						continue
					}
					if regexp.MustCompile(`^\d{1,5}-\d{1,5}$`).MatchString(p) {
						rp := strings.Split(p, "-")
						portfrom, err := strconv.ParseUint(rp[0], 10, 16)
						if err != nil {
							return errors.New("端口:" + rp[0] + " 格式错误, " + err.Error())
						}
						portto, err := strconv.ParseUint(rp[1], 10, 16)
						if err != nil {
							return errors.New("端口:" + rp[1] + " 格式错误, " + err.Error())
						}
						if portfrom > portto {
							return fmt.Errorf("端口范围错误: 起始端口 %d 大于结束端口 %d", portfrom, portto)
						}
						if portto-portfrom > 1000 {
							ports[0] = 1
						} else {
							for i := portfrom; i <= portto; i++ {
								ports[uint16(i)] = 1
							}
						}
					} else {
						port, err := strconv.ParseUint(p, 10, 16)
						if err != nil {
							return errors.New("端口:" + p + " 格式错误, " + err.Error())
						}
						ports[uint16(port)] = 1
					}
				}
				v.Ports = ports
				linkAcl = append(linkAcl, v)
			} else {
				return errors.New("端口: " + portsStr + " 格式错误,请用逗号分隔的端口,比如: 22,80,443 连续端口用-,比如:1234-5678")
			}
		}
	}
	p.LinkAcl = linkAcl

	p.UpdatedAt = time.Now()
	if p.Id > 0 {
		err = Set(p)
	} else {
		err = Add(p)
	}

	return err
}
