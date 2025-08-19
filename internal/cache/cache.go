package cache

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	alpha1v1 "github.com/linode/cloud-firewall-controller/api/alpha1v1"
	"github.com/linode/cloud-firewall-controller/internal/rules"
	lgo "github.com/linode/linodego"
	"k8s.io/klog/v2"
)

type CloudFirewallCache struct {
	// these are ordered for optimal structure, not alpha
	firewallSpecs map[string]alpha1v1.CloudFirewallSpec
	defaultSpec   alpha1v1.RulesetSpec
	primaryKey    string
	firewallNames []string
}

func NewCloudFirewallCache(primaryName string, primaryNs string) *CloudFirewallCache {
	cache := &CloudFirewallCache{
		primaryKey:    getKey(primaryName, primaryNs),
		defaultSpec:   rules.DefaultRuleset(),
		firewallSpecs: make(map[string]alpha1v1.CloudFirewallSpec),
		firewallNames: []string{},
	}
	return cache
}

func getKey(name string, ns string) string {
	return name + "-" + ns
}

func (c *CloudFirewallCache) Remove(name string, ns string) {
	var updatedNames []string
	key := getKey(name, ns)
	for _, name := range c.firewallNames {
		if name != key {
			updatedNames = append(updatedNames, name)
		} else {
			klog.V(5).Infof("Removing cache entry for key: %s", key)
		}
	}
	c.firewallNames = updatedNames

	delete(c.firewallSpecs, key)
}

func (c *CloudFirewallCache) Update(name string, ns string, cfw alpha1v1.CloudFirewallSpec) {
	key := getKey(name, ns)
	if slices.Contains(c.firewallNames, key) {
		klog.V(5).Infof("[%s/%s] updating cache entry: %v", name, ns, cfw)
		c.firewallSpecs[key] = cfw
	} else {
		klog.V(5).Infof("[%s/%s] adding cache entry: %v", name, ns, cfw)
		c.Add(name, ns, cfw)
	}
}

func (c *CloudFirewallCache) Add(name string, ns string, cfw alpha1v1.CloudFirewallSpec) {
	key := getKey(name, ns)

	if slices.Contains(c.firewallNames, key) {
		klog.Errorf("[%s/%s] cache insert failed, duplicate key detected.", name, ns)
		return
	}
	c.firewallNames = append(c.firewallNames, key)
	sort.Strings(c.firewallNames)
	c.firewallSpecs[key] = cfw
}

func (c *CloudFirewallCache) GetLatestLinodeRuleset() (lgo.FirewallRuleSet, error) {
	ruleset := c.defaultSpec
	var lrs lgo.FirewallRuleSet
	var err error

	klog.V(5).Infof("Base Ruleset: %v", ruleset)
	klog.V(5).Infof("Firewall Names: %v", c.firewallNames)
	for _, specKey := range c.firewallNames {
		if specKey != c.primaryKey {
			ruleset.Inbound = append(ruleset.Inbound, c.firewallSpecs[specKey].Ruleset.Inbound...)
			ruleset.Outbound = append(ruleset.Outbound, c.firewallSpecs[specKey].Ruleset.Outbound...)
		}
	}

	rulesetStr, err := json.Marshal(ruleset)
	if err != nil {
		return lgo.FirewallRuleSet{}, fmt.Errorf("unable to marshal CloudFirewall ruleset - %s", err.Error())
	}

	err = json.Unmarshal(rulesetStr, &lrs)
	if err != nil {
		return lgo.FirewallRuleSet{}, fmt.Errorf("unable to unmarshal CloudFirewall ruleset - %s", err.Error())
	}

	return lrs, nil
}
