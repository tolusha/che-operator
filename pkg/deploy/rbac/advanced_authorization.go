//
// Copyright (c) 2019-2026 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

package rbac

import (
	"context"

	chev2 "github.com/eclipse-che/che-operator/api/v2"
)

// isEmptyPolicy returns true when none of the allow/deny lists are populated.
func isEmptyPolicy(policy chev2.AdvancedAuthorization) bool {
	return len(policy.AllowUsers) == 0 &&
		len(policy.AllowGroups) == 0 &&
		len(policy.DenyUsers) == 0 &&
		len(policy.DenyGroups) == 0
}

// IsUserPermitted evaluates the AdvancedAuthorization policy for the given user.
// Deny list is evaluated before allow list.
func IsUserPermitted(ctx context.Context, username string, resolver GroupResolver, policy chev2.AdvancedAuthorization) (bool, error) {
	// (1) Empty policy — permit everyone.
	if isEmptyPolicy(policy) {
		return true, nil
	}

	// Resolve groups only when needed (deny or allow groups are configured).
	var groups []string
	if len(policy.DenyGroups) > 0 || len(policy.AllowGroups) > 0 {
		var err error
		groups, err = resolver.GetUserGroups(ctx, username)
		if err != nil {
			return false, err
		}
	}

	// (2) Deny-list check.
	for _, u := range policy.DenyUsers {
		if u == username {
			return false, nil
		}
	}
	for _, g := range groups {
		for _, dg := range policy.DenyGroups {
			if g == dg {
				return false, nil
			}
		}
	}

	// (3) Allow-list check.
	if len(policy.AllowUsers) > 0 || len(policy.AllowGroups) > 0 {
		for _, u := range policy.AllowUsers {
			if u == username {
				return true, nil
			}
		}
		for _, g := range groups {
			for _, ag := range policy.AllowGroups {
				if g == ag {
					return true, nil
				}
			}
		}
		// (4) Allow-list defined but user matched nothing.
		return false, nil
	}

	// (5) No allow-list, deny-list not matched — permit.
	return true, nil
}
