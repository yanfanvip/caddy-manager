package utils

import (
	"net"

	"github.com/phuslu/iploc"
)

// CountryInfo 国家信息
type CountryInfo struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// CountryNames 国家代码 → 中文名
var CountryNames = map[string]string{
	"CN": "中国大陆",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
	"JP": "日本",
	"KR": "韩国",
	"SG": "新加坡",
	"US": "美国",
	"DE": "德国",
	"GB": "英国",
	"FR": "法国",
	"RU": "俄罗斯",
	"AU": "澳大利亚",
	"CA": "加拿大",
	"IN": "印度",
	"NL": "荷兰",
	"BR": "巴西",
	"TH": "泰国",
	"VN": "越南",
	"ID": "印度尼西亚",
	"MY": "马来西亚",
	"PH": "菲律宾",
	"IT": "意大利",
	"ES": "西班牙",
	"SE": "瑞典",
	"CH": "瑞士",
	"PL": "波兰",
	"UA": "乌克兰",
	"TR": "土耳其",
	"SA": "沙特阿拉伯",
	"AE": "阿联酋",
	"ZA": "南非",
	"MX": "墨西哥",
	"AR": "阿根廷",
}

// LookupCountry 查询 IP 归属国家，返回国家代码和中文名
// 底层使用 github.com/phuslu/iploc，数据内嵌于库中，无需外部文件
func LookupCountry(ip string) (code, name string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", ""
	}
	code = iploc.Country(parsed)
	if code == "" {
		return "", ""
	}
	name = CountryNames[code]
	if name == "" {
		name = code
	}
	return code, name
}

