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
	"testing"

	"github.com/ory/ladon"
)

func TestInterfaceType(t *testing.T) {
	var m interface{} = &Manager{}
	if _, ok := m.(ladon.Manager); !ok {
		t.Fatalf("Manager does not satisfy ladon.Manager interface")
	}
}
