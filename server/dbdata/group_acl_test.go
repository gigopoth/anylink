package dbdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetGroupLinkAcl(t *testing.T) {
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// 正常ACL规则
	g := Group{
		Name:      "acl_test1",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "192.168.1.0/24", Protocol: TCP, Port: "80,443"},
			{Action: Deny, Val: "0.0.0.0/0", Protocol: ALL, Port: "0"},
		},
	}
	err := SetGroup(&g)
	ast.Nil(err)
	// 验证ACL规则已正确解析
	ast.Equal(2, len(g.LinkAcl))
	ast.NotNil(g.LinkAcl[0].IpNet)
	ast.NotNil(g.LinkAcl[0].Ports)
	ast.Equal(true, ContainsInPorts(g.LinkAcl[0].Ports, 80))
	ast.Equal(true, ContainsInPorts(g.LinkAcl[0].Ports, 443))

	// 无效协议类型应返回错误
	g2 := Group{
		Name:      "acl_test2",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: "tpc", Port: "80"},
		},
	}
	err = SetGroup(&g2)
	ast.NotNil(err)
	ast.Contains(err.Error(), "不支持的协议类型")

	// 端口范围倒序应返回错误
	g3 := Group{
		Name:      "acl_test3",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: TCP, Port: "5000-1000"},
		},
	}
	err = SetGroup(&g3)
	ast.NotNil(err)
	ast.Contains(err.Error(), "端口范围错误")

	// 大端口范围应使用通配符 (port 0)
	g4 := Group{
		Name:      "acl_test4",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: TCP, Port: "1-65535"},
		},
	}
	err = SetGroup(&g4)
	ast.Nil(err)
	ast.Equal(1, len(g4.LinkAcl))
	// 大范围应转换为通配符(端口0)
	ast.Equal(true, ContainsInPorts(g4.LinkAcl[0].Ports, 0))
	// 不应逐个展开
	ast.True(len(g4.LinkAcl[0].Ports) < 100)

	// 空协议应默认为ALL
	g5 := Group{
		Name:      "acl_test5",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: "", Port: "80"},
		},
	}
	err = SetGroup(&g5)
	ast.Nil(err)
	ast.Equal(ALL, g5.LinkAcl[0].Protocol)

	// 无效CIDR应返回错误
	g6 := Group{
		Name:      "acl_test6",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "invalid-cidr", Protocol: TCP, Port: "80"},
		},
	}
	err = SetGroup(&g6)
	ast.NotNil(err)
	ast.Contains(err.Error(), "GroupLinkAcl 错误")

	// 无效端口格式应返回错误
	g7 := Group{
		Name:      "acl_test7",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: TCP, Port: "abc"},
		},
	}
	err = SetGroup(&g7)
	ast.NotNil(err)
	ast.Contains(err.Error(), "端口")

	// ICMP协议正常工作
	g8 := Group{
		Name:      "acl_test8",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: ICMP, Port: "0"},
		},
	}
	err = SetGroup(&g8)
	ast.Nil(err)
	ast.Equal(ICMP, g8.LinkAcl[0].Protocol)

	// UDP协议正常工作
	g9 := Group{
		Name:      "acl_test9",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: UDP, Port: "53"},
		},
	}
	err = SetGroup(&g9)
	ast.Nil(err)
	ast.Equal(UDP, g9.LinkAcl[0].Protocol)
}

func TestSetPolicyLinkAcl(t *testing.T) {
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// Policy 支持 LinkAcl
	p1 := Policy{
		Username:  "acl_user1",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "192.168.1.0/24", Protocol: TCP, Port: "80,443"},
			{Action: Deny, Val: "0.0.0.0/0", Protocol: ALL, Port: "0"},
		},
	}
	err := SetPolicy(&p1)
	ast.Nil(err)
	ast.Equal(2, len(p1.LinkAcl))
	ast.NotNil(p1.LinkAcl[0].IpNet)

	// Policy 无效协议应返回错误
	p2 := Policy{
		Username:  "acl_user2",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: "xyz", Port: "80"},
		},
	}
	err = SetPolicy(&p2)
	ast.NotNil(err)
	ast.Contains(err.Error(), "不支持的协议类型")

	// Policy 端口范围倒序应返回错误
	p3 := Policy{
		Username:  "acl_user3",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		LinkAcl: []GroupLinkAcl{
			{Action: Allow, Val: "10.0.0.0/8", Protocol: TCP, Port: "5000-1000"},
		},
	}
	err = SetPolicy(&p3)
	ast.NotNil(err)
	ast.Contains(err.Error(), "端口范围错误")
}

func TestContainsInPorts(t *testing.T) {
	ast := assert.New(t)

	ports := map[uint16]int8{80: 1, 443: 1, 0: 1}
	ast.True(ContainsInPorts(ports, 80))
	ast.True(ContainsInPorts(ports, 443))
	ast.True(ContainsInPorts(ports, 0)) // 通配符
	ast.False(ContainsInPorts(ports, 8080))
}
