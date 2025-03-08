package unifi

type USP struct {
	UAP
	OutletOverrides []*struct {
		OutletOverride
	} `json:"outlet_overrides"`
	OutletEnabled bool `json:"outlet_enabled"`
	OutletTable   []*struct {
		Index        int    `json:"index"`
		HasRelay     bool   `json:"has_relay"`
		HasMetering  bool   `json:"has_metering"`
		RelayState   bool   `json:"relay_state"`
		CycleEnabled bool   `json:"cycle_enabled"`
		Name         string `json:"name"`
	} `json:"outlet_table"`
}

type OutletOverrides struct {
	OutletOverrides []*struct {
		OutletOverride
	} `json:"outlet_overrides"`
}

func (usp *USP) GetSite() *Site {
	return usp.site
}
