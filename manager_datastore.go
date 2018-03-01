/*
 * Copyright © 2018 Prateek Malhotra <someone1@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 * Based on https://github.com/ory/ladon/blob/master/manager/sql/manager_sql.go
 */

package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/datastore"
	"github.com/ory/ladon"
	"github.com/pkg/errors"
)

const (
	ladonPolicyKind = "LadonPolicy"
	version         = 1
)

// ladonPolicy is used to represent a ladon.Policy in Google's Datastore
type ladonPolicy struct {
	Key         *datastore.Key       `datastore:"-"`
	ID          string               `datastore:"-"`
	Description string               `datastore:"d,noindex"`
	Effect      string               `datastore:"e"`
	Conditions  []byte               `datastore:"c,noindex"`
	Subjects    []LadonPolicyMatcher `datastore:"s"`
	Resources   []LadonPolicyMatcher `datastore:"r,noindex"`
	Actions     []LadonPolicyMatcher `datastore:"a,noindex"`
	Version     int                  `datastore:"v"`

	update bool
}

// LadonPolicyMatcher is used to represent Policy matching templates
type LadonPolicyMatcher struct {
	Template string `datastore:"t"`
	HasRegex bool   `datastore:"h"`
}

// LoadKey is implemented for the KeyLoader interface
func (l *ladonPolicy) LoadKey(k *datastore.Key) error {
	l.Key = k
	l.ID = k.Name

	return nil
}

// Load is implemented for the PropertyLoadSaver interface, and performs schema migration if necessary
func (l *ladonPolicy) Load(ps []datastore.Property) error {
	err := datastore.LoadStruct(l, ps)
	if _, ok := err.(*datastore.ErrFieldMismatch); err != nil && !ok {
		return errors.WithStack(err)
	}

	switch l.Version {
	case version:
		// Up to date, nothing to do
		break
	// case 1:
	// 	// Update to version 2 here
	// 	fallthrough
	// case 2:
	// 	//update to version 3 here
	// 	fallthrough
	case -1:
		// This is here to complete saving the entity should we need to udpate it
		if l.Version == -1 {
			return errors.New(fmt.Sprintf("unexpectedly got to version update trigger with incorrect version -1"))
		}
		l.update = true
	default:
		return errors.New(fmt.Sprintf("got unexpected version %d when loading entity", l.Version))
	}
	return nil
}

// Save is implemented for the PropertyLoadSaver interface, and enforces the effect values of allow/deny
func (l *ladonPolicy) Save() ([]datastore.Property, error) {
	l.Version = version
	switch l.Effect {
	case "allow", "deny":
	default:
		return nil, errors.New(fmt.Sprintf("got unexpected value for effect: %s", l.Effect))
	}
	return datastore.SaveStruct(l)
}

// Manager is a Google Datastore implementation for Manager to store policies persistently.
type Manager struct {
	client    *datastore.Client
	context   context.Context
	namespace string
}

// NewManager initializes a new Manager with the given client
func NewManager(ctx context.Context, client *datastore.Client, namespace string) *Manager {
	return &Manager{
		context:   ctx,
		client:    client,
		namespace: namespace,
	}
}

func (m *Manager) createPolicyKey(policyID string) *datastore.Key {
	key := datastore.NameKey(ladonPolicyKind, policyID, nil)
	key.Namespace = m.namespace
	return key
}

func (m *Manager) updatePolicyVersionMulti(keys []*datastore.Key) error {
	chunkSize := 25 // Max Entity Groups per transactions
	for i := 0; i < len(keys); i += chunkSize {
		end := i + chunkSize
		if end > len(keys) {
			end = len(keys)
		}

		_, err := m.client.RunInTransaction(m.context, func(tx *datastore.Transaction) error {
			var policies []ladonPolicy

			if terr := tx.GetMulti(keys[i:end], &policies); terr != nil {
				return errors.WithStack(terr)
			}
			var toUpdate []*datastore.Mutation

			for idx := range policies {
				if policies[idx].update {
					toUpdate = append(toUpdate, datastore.NewUpdate(policies[idx].Key, &policies[idx]))
				}
			}

			if len(toUpdate) > 0 {
				if _, terr := tx.Mutate(toUpdate...); terr != nil {
					return errors.WithStack(terr)
				}
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// Update updates an existing policy.
func (m *Manager) Update(policy ladon.Policy) error {
	key := m.createPolicyKey(policy.GetID())
	convertedPolicy, err := convertPolicy(policy)
	if err != nil {
		return errors.WithStack(err)
	}

	mutation := datastore.NewUpdate(key, convertedPolicy)

	_, err = m.client.RunInTransaction(m.context, func(tx *datastore.Transaction) error {
		if _, terr := tx.Mutate(mutation); terr != nil {
			return errors.WithStack(terr)
		}
		return nil
	})

	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Create inserts a new policy
func (m *Manager) Create(policy ladon.Policy) (err error) {
	key := m.createPolicyKey(policy.GetID())
	convertedPolicy, err := convertPolicy(policy)
	if err != nil {
		return errors.WithStack(err)
	}

	mutation := datastore.NewInsert(key, convertedPolicy)

	_, err = m.client.RunInTransaction(m.context, func(tx *datastore.Transaction) error {
		if _, terr := tx.Mutate(mutation); terr != nil {
			return errors.WithStack(terr)
		}
		return nil
	})

	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func genMatchers(policy ladon.Policy, templates []string) ([]LadonPolicyMatcher, error) {
	var matchers []LadonPolicyMatcher
	for _, template := range uniq(templates) {
		matchers = append(matchers, LadonPolicyMatcher{
			Template: template,
			HasRegex: strings.Contains(template, string(policy.GetStartDelimiter())),
		})
	}
	return matchers, nil
}

func convertPolicy(policy ladon.Policy) (dPolicy *ladonPolicy, err error) {
	conditions := []byte("{}")
	if policy.GetConditions() != nil {
		cs := policy.GetConditions()
		conditions, err = json.Marshal(&cs)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	dPolicy = &ladonPolicy{
		Description: policy.GetDescription(),
		Effect:      policy.GetEffect(),
		Conditions:  conditions,
	}

	// Matchers
	dPolicy.Actions, err = genMatchers(policy, policy.GetActions())
	if err != nil {
		return nil, err
	}
	dPolicy.Resources, err = genMatchers(policy, policy.GetResources())
	if err != nil {
		return nil, err
	}
	dPolicy.Subjects, err = genMatchers(policy, policy.GetSubjects())
	if err != nil {
		return nil, err
	}

	return dPolicy, nil
}

func (l *ladonPolicy) convertToPolicy() (ladon.Policy, error) {
	policy := new(ladon.DefaultPolicy)
	policy.Description = l.Description
	policy.ID = l.ID
	policy.Effect = l.Effect
	policy.Conditions = ladon.Conditions{}

	if err := json.Unmarshal(l.Conditions, &policy.Conditions); err != nil {
		return nil, errors.WithStack(err)
	}

	for _, matcher := range l.Actions {
		policy.Actions = append(policy.Actions, matcher.Template)
	}

	for _, matcher := range l.Resources {
		policy.Resources = append(policy.Resources, matcher.Template)
	}

	for _, matcher := range l.Subjects {
		policy.Subjects = append(policy.Subjects, matcher.Template)
	}

	return policy, nil
}

// FindRequestCandidates returns candidates that could match the request object. It either returns
// a set that exactly matches the request, or a superset of it. If an error occurs, it returns nil and
// the error.
func (m *Manager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	// Need Two Queries

	// First, find all plain matches
	query := datastore.NewQuery(ladonPolicyKind).Filter("s.t =", r.Subject).Filter("s.h =", false).Namespace(m.namespace)
	policies, err := m.executeQuery(query)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	found := make(map[string]interface{})
	for _, policy := range policies {
		found[policy.GetID()] = nil
	}

	// Second, get ALL regex templates to match off of, skipping policies we already found
	query = datastore.NewQuery(ladonPolicyKind).Filter("s.h =", true).Namespace(m.namespace)
	regexpolicies, rerr := m.executeQuery(query)
	if rerr != nil {
		return nil, errors.WithStack(rerr)
	}
	for _, policy := range regexpolicies {
		if _, ok := found[policy.GetID()]; !ok {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// GetAll returns all policies
func (m *Manager) GetAll(limit, offset int64) (ladon.Policies, error) {
	query := datastore.NewQuery(ladonPolicyKind).Offset(int(offset)).Limit(int(limit)).Order("__key__").Namespace(m.namespace)

	return m.executeQuery(query)
}

func (m *Manager) executeQuery(query *datastore.Query) (ladon.Policies, error) {
	var policies []ladonPolicy
	var lPolicies ladon.Policies

	if _, err := m.client.GetAll(m.context, query, &policies); err != nil {
		return nil, errors.WithStack(err)
	}

	// Let's check if we need to update any policies
	var keys []*datastore.Key
	for _, policy := range policies {
		if lp, err := policy.convertToPolicy(); err == nil {
			lPolicies = append(lPolicies, lp)
		} else {
			return nil, errors.WithStack(err)
		}
		if policy.update {
			keys = append(keys, policy.Key)
			policy.update = false
		}
	}

	if len(keys) > 0 {
		if err := m.updatePolicyVersionMulti(keys); err != nil {
			return nil, err
		}
	}

	return lPolicies, nil
}

// Get retrieves a policy.
func (m *Manager) Get(id string) (ladon.Policy, error) {
	key := m.createPolicyKey(id)
	var policy ladonPolicy

	if err := m.client.Get(m.context, key, &policy); err == datastore.ErrNoSuchEntity {
		return nil, ladon.NewErrResourceNotFound(err)
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	if policy.update {
		if err := m.updatePolicyVersionMulti([]*datastore.Key{policy.Key}); err != nil {
			return nil, err
		}
		policy.update = false
	}

	return policy.convertToPolicy()
}

// Delete removes a policy.
func (m *Manager) Delete(id string) error {
	key := m.createPolicyKey(id)
	_, err := m.client.RunInTransaction(m.context, func(tx *datastore.Transaction) error {
		if terr := tx.Delete(key); terr != nil {
			return errors.WithStack(terr)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func uniq(input []string) []string {
	u := make([]string, 0, len(input))
	m := make(map[string]bool)

	for _, val := range input {
		if _, ok := m[val]; !ok {
			m[val] = true
			u = append(u, val)
		}
	}

	return u
}

func typecheck() {
	var _ ladon.Manager = (*Manager)(nil)
}
