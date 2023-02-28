// Package udger package allow you to load in memory and lookup the user agent database to extract value from the provided user agent
package udger

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"net"
	"os"
	"regexp"
	"strings"
)

// New creates a new instance of Udger and load all the database in memory to allow fast lookup
// you need to pass the sqlite database in parameter
func New(dbPath string) (Client, error) {
	u := &udger{
		Browsers:         make(map[int]Browser),
		OS:               make(map[int]OS),
		Devices:          make(map[int]Device),
		IP:               make(map[string]IP),
		IPClass:          make(map[int]IPClass),
		Crawler:          make(map[int]Crawler),
		CrawlerClass:     make(map[int]CrawlerClass),
		DataCenter:       make(map[int]DataCenter),
		DataCenterRange:  make([]DataCenterRange, 0),
		DataCenterRange6: make([]DataCenterRange6, 0),
		browserTypes:     make(map[int]string),
		browserOS:        make(map[int]int),
	}
	var err error

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, err
	}

	u.db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer u.db.Close()

	err = u.init()
	if err != nil {
		return nil, err
	}

	return u, nil
}

// Lookup one user agent and return a Info struct who contains all the metadata possible for the UA.
func (u *udger) Lookup(ua string) (*Info, error) {
	info := &Info{}

	browserID, version, err := u.findDataWithVersion(ua, u.rexBrowsers, true)
	if err != nil {
		return nil, err
	}

	info.Browser = u.Browsers[browserID]
	if info.Browser.Family != "" {
		info.Browser.Name = info.Browser.Family + " " + version
	}
	info.Browser.Version = version
	info.Browser.Type = u.browserTypes[info.Browser.typ]

	if val, ok := u.browserOS[browserID]; ok {
		info.OS = u.OS[val]
	} else {
		osID, _, err := u.findData(ua, u.rexOS, false)
		if err != nil {
			return nil, err
		}
		info.OS = u.OS[osID]
	}

	deviceID, _, err := u.findData(ua, u.rexDevices, false)
	if err != nil {
		return nil, err
	}
	if val, ok := u.Devices[deviceID]; ok {
		info.Device = val
	} else if info.Browser.typ == 3 { // if browser is mobile, we can guess its a mobile
		info.Device = Device{
			Name: "Smartphone",
			Icon: "phone.png",
		}
	} else if info.Browser.typ == 5 || info.Browser.typ == 10 || info.Browser.typ == 20 || info.Browser.typ == 50 {
		info.Device = Device{
			Name: "Other",
			Icon: "other.png",
		}
	} else {
		//nothing so personal computer
		info.Device = Device{
			Name: "Personal computer",
			Icon: "desktop.png",
		}
	}

	return info, nil
}

func (u *udger) LookupIP(ip net.IP) (*IPInfo, error) {
	info := &IPInfo{}

	var ipVersion byte
	if ip.To4() == nil {
		ipVersion = 6
	} else {
		ipVersion = 4
	}

	uIP, ok := u.IP[ip.String()]
	if ok {
		info.IP = uIP
		uIPClass, classok := u.IPClass[uIP.ClassID]
		if classok {
			info.IPClass = uIPClass
		}
		uCrawler, crawlerok := u.Crawler[uIP.CrawlerID]
		if crawlerok {
			info.Crawler = uCrawler
			uCrawlerClass, crawlerclassok := u.CrawlerClass[uCrawler.ClassID]
			if crawlerclassok {
				info.CrawlerClass = uCrawlerClass
			}
		}
	}

	if ipVersion == 4 {
		ip4 := ip.To4()

		if ip4 != nil {
			ipInt := int(binary.BigEndian.Uint32(ip4))
			for _, dcr := range u.DataCenterRange {
				if ipInt >= dcr.IPLongFrom && ipInt <= dcr.IPLongTo {
					info.DataCenterRange = dcr
					dc, ok := u.DataCenter[dcr.DatacenterID]
					if ok {
						info.DataCenter = dc
					}
					break
				}
			}
		}
	} else {
		ip16 := ip.To16()

		if ip16 != nil {
			for _, dcr := range u.DataCenterRange6 {
				from16 := net.ParseIP(dcr.IPFrom).To16()
				to16 := net.ParseIP(dcr.IPTo).To16()
				if from16 != nil && to16 != nil {
					if bytes.Compare(ip16, from16) >= 0 && bytes.Compare(ip16, to16) <= 0 {
						info.DataCenterRange6 = dcr
						dc, ok := u.DataCenter[dcr.DatacenterID]
						if ok {
							info.DataCenter = dc
						}
						break
					}
				}
			}
		}
	}

	return info, nil
}

func (u *udger) cleanRegex(r string) string {
	if strings.HasSuffix(r, "/si") {
		r = r[:len(r)-3]
	}
	if strings.HasPrefix(r, "/") {
		r = r[1:]
	}

	return r
}

func (u *udger) findDataWithVersion(ua string, data []rexData, withVersion bool) (idx int, value string, err error) {
	defer func() {
		if r := recover(); r != nil {
			idx, value, err = u.findData(ua, data, false)
		}
	}()

	idx, value, err = u.findData(ua, data, withVersion)

	return idx, value, err
}

func (u *udger) findData(ua string, data []rexData, withVersion bool) (idx int, value string, err error) {
	for i := 0; i < len(data); i++ {
		r := data[i].RegexCompiled
		if !r.MatchString(ua) {
			continue
		}

		// TODO: implement regex for browser version and name support
		//if withVersion && matcher.Present(1) {
		//return data[i].ID, matcher.GroupString(1), nil
		//}

		return data[i].ID, "", nil
	}

	return -1, "", nil
}

func (u *udger) init() error {
	rows, err := u.db.Query("SELECT client_id, regstring FROM udger_client_regex ORDER by sequence ASC")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d rexData
		rows.Scan(&d.ID, &d.Regex)
		d.Regex = u.cleanRegex(d.Regex)
		r, err := regexp.Compile("(?i)" + d.Regex)
		if err != nil {
			return err
		}
		d.RegexCompiled = r
		u.rexBrowsers = append(u.rexBrowsers, d)
	}
	rows.Close()

	rows, err = u.db.Query("SELECT deviceclass_id, regstring FROM udger_deviceclass_regex ORDER by sequence ASC")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d rexData
		rows.Scan(&d.ID, &d.Regex)
		d.Regex = u.cleanRegex(d.Regex)
		r, err := regexp.Compile("(?i)" + d.Regex)
		if err != nil {
			return err
		}
		d.RegexCompiled = r
		u.rexDevices = append(u.rexDevices, d)
	}
	rows.Close()

	rows, err = u.db.Query("SELECT os_id, regstring FROM udger_os_regex ORDER by sequence ASC")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d rexData
		rows.Scan(&d.ID, &d.Regex)
		d.Regex = u.cleanRegex(d.Regex)
		r, err := regexp.Compile("(?i)" + d.Regex)
		if err != nil {
			return err
		}
		d.RegexCompiled = r
		u.rexOS = append(u.rexOS, d)
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, class_id, name,engine,vendor,icon FROM udger_client_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d Browser
		var id int
		rows.Scan(&id, &d.typ, &d.Family, &d.Engine, &d.Company, &d.Icon)
		u.Browsers[id] = d
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, name, family, vendor, icon FROM udger_os_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d OS
		var id int
		rows.Scan(&id, &d.Name, &d.Family, &d.Company, &d.Icon)
		u.OS[id] = d
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, name, icon FROM udger_deviceclass_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d Device
		var id int
		rows.Scan(&id, &d.Name, &d.Icon)
		u.Devices[id] = d
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, client_classification FROM udger_client_class")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d string
		var id int
		rows.Scan(&id, &d)
		u.browserTypes[id] = d
	}
	rows.Close()

	rows, err = u.db.Query("SELECT client_id, os_id FROM udger_client_os_relation")
	if err != nil {
		return err
	}
	for rows.Next() {
		var browser int
		var os int
		rows.Scan(&browser, &os)
		u.browserOS[browser] = os
	}
	rows.Close()

	rows, err = u.db.Query("SELECT ip, class_id, crawler_id, ip_last_seen, ip_hostname, ip_country, ip_city, ip_country_code FROM udger_ip_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip IP
		rows.Scan(&ip.IP, &ip.ClassID, &ip.CrawlerID, &ip.IPLastSeen, &ip.IPHostname, &ip.IPCountry, &ip.IPCity, &ip.IPCountryCode)
		u.IP[ip.IP] = ip
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, ua_string, ver, ver_major, class_id, last_seen, respect_robotstxt, family, family_code, family_homepage, family_icon, vendor, vendor_code, vendor_homepage, name FROM udger_crawler_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var c Crawler
		rows.Scan(&c.ID, &c.UA, &c.Ver, &c.VerMajor, &c.ClassID, &c.LastSeen, &c.RespectRobotstxt, &c.Family, &c.FamilyCode, &c.FamilyHomepage, &c.FamilyIcon, &c.Vendor, &c.VendorCode, &c.VendorHomepage, &c.Name)
		u.Crawler[c.ID] = c
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, ip_classification, ip_classification_code FROM udger_ip_class")
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip IPClass
		rows.Scan(&ip.ID, &ip.IPClassification, &ip.IPClassificationCode)
		u.IPClass[ip.ID] = ip
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, crawler_classification, crawler_classification_code FROM udger_crawler_class")
	if err != nil {
		return err
	}
	for rows.Next() {
		var c CrawlerClass
		rows.Scan(&c.ID, &c.CrawlerClassification, &c.CrawlerClassificationCode)
		u.CrawlerClass[c.ID] = c
	}
	rows.Close()

	rows, err = u.db.Query("SELECT id, name, name_code, homepage FROM udger_datacenter_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d DataCenter
		rows.Scan(&d.ID, &d.Name, &d.NameCode, &d.Homepage)
		u.DataCenter[d.ID] = d
	}
	rows.Close()

	rows, err = u.db.Query("SELECT datacenter_id, ip_from, ip_to, iplong_from, iplong_to FROM udger_datacenter_range")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d DataCenterRange
		rows.Scan(&d.DatacenterID, &d.IPFrom, &d.IPTo, &d.IPLongFrom, &d.IPLongTo)
		u.DataCenterRange = append(u.DataCenterRange, d)
	}
	rows.Close()

	rows, err = u.db.Query("SELECT datacenter_id, ip_from, ip_to, iplong_from0, iplong_from1, iplong_from2, iplong_from3, iplong_from4, iplong_from5, iplong_from6, iplong_from7, iplong_to0, iplong_to1, iplong_to2, iplong_to3, iplong_to4, iplong_to5, iplong_to6, iplong_to7 FROM udger_datacenter_range6")
	if err != nil {
		return err
	}
	for rows.Next() {
		var d DataCenterRange6
		rows.Scan(&d.DatacenterID, &d.IPFrom, &d.IPTo, &d.IPLongFrom0, &d.IPLongFrom1, &d.IPLongFrom2, &d.IPLongFrom3, &d.IPLongFrom4, &d.IPLongFrom5, &d.IPLongFrom6, &d.IPLongFrom7, &d.IPLongTo0, &d.IPLongTo1, &d.IPLongTo2, &d.IPLongTo3, &d.IPLongTo4, &d.IPLongTo5, &d.IPLongTo6, &d.IPLongTo7)
		u.DataCenterRange6 = append(u.DataCenterRange6, d)
	}
	rows.Close()

	return nil
}
