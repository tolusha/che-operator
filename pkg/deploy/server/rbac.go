//
// Copyright (c) 2019-2023 Red Hat, Inc.
// This program and the accompanying materials are made
// available under the terms of the Eclipse Public License 2.0
// which is available at https://www.eclipse.org/legal/epl-2.0/
//
// SPDX-License-Identifier: EPL-2.0
//
// Contributors:
//   Red Hat, Inc. - initial API and implementation
//

package server

// HANDOFF-FOR-T3: preserved policy rules
//
// getUserCommonPolicies (formerly used for <ns>-cheworkspaces-clusterrole):
//
//   k8sPolicies:
//     - APIGroups: [""]           Resources: ["pods/exec"]               Verbs: ["get", "create"]
//     - APIGroups: [""]           Resources: ["pods/log"]                Verbs: ["get", "list", "watch"]
//     - APIGroups: [""]           Resources: ["pods/portforward"]        Verbs: ["get", "list", "create"]
//     - APIGroups: [""]           Resources: ["secrets"]                 Verbs: ["get", "list", "create", "update", "patch", "delete"]
//     - APIGroups: [""]           Resources: ["persistentvolumeclaims"]  Verbs: ["get", "list", "watch", "create", "delete", "update", "patch"]
//     - APIGroups: [""]           Resources: ["pods"]                    Verbs: ["get", "list", "watch", "create", "delete", "update", "patch"]
//     - APIGroups: [""]           Resources: ["services"]                Verbs: ["get", "list", "create", "delete", "update", "patch"]
//     - APIGroups: [""]           Resources: ["configmaps"]              Verbs: ["get", "list", "create", "update", "patch", "delete"]
//     - APIGroups: ["apps"]       Resources: ["deployments"]             Verbs: ["get", "list", "watch", "create", "patch", "delete"]
//     - APIGroups: ["apps"]       Resources: ["replicasets"]             Verbs: ["get", "list", "patch", "delete"]
//     - APIGroups: ["networking.k8s.io"] Resources: ["ingresses"]        Verbs: ["get", "list", "watch", "create", "delete"]
//     - APIGroups: ["metrics.k8s.io"]   Resources: ["pods", "nodes"]    Verbs: ["get", "list", "watch"]
//     - APIGroups: [""]           Resources: ["namespaces"]              Verbs: ["get", "list"]
//     - APIGroups: [""]           Resources: ["events"]                  Verbs: ["watch", "list"]
//   openshiftPolicies (appended on OpenShift):
//     - APIGroups: ["route.openshift.io"] Resources: ["routes"]          Verbs: ["get", "list", "create", "delete"]
//     - APIGroups: ["project.openshift.io"] Resources: ["projects"]      Verbs: ["get"]
//
// getUserDevWorkspacePolicies (formerly used for <ns>-cheworkspaces-devworkspace-clusterrole):
//
//   k8sPolicies:
//     - APIGroups: ["workspace.devfile.io"] Resources: ["devworkspaces", "devworkspacetemplates"]
//       Verbs: ["get", "create", "delete", "list", "update", "patch", "watch"]

import (
	"fmt"
	"strings"

	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	util "github.com/eclipse-che/che-operator/pkg/common/utils"
	"github.com/sirupsen/logrus"

	"github.com/eclipse-che/che-operator/pkg/common/chetypes"
	"github.com/eclipse-che/che-operator/pkg/common/constants"
	"github.com/eclipse-che/che-operator/pkg/deploy"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// userCommonPermissionsTemplateName and userDevWorkspacePermissionsTemplateName are kept as
	// package-level aliases of the exported constants so that existing test code in this package
	// continues to compile. The authoritative definitions have been moved to the constants package
	// so that T3 (pkg/deploy/rbac/) and T5 (controllers/usernamespace/) can also reference them.
	userCommonPermissionsTemplateName       = constants.UserCommonPermissionsTemplateName
	userDevWorkspacePermissionsTemplateName = constants.UserDevWorkspacePermissionsTemplateName
	cheSASpecificPermissionsTemplateName    = "%s-cheworkspaces-namespaces-clusterrole"
)

// Create ClusterRole and ClusterRoleBinding for "che" service account.
// che-server uses "che" service account for creation RBAC for a user in his namespace.
func (s *CheServerReconciler) syncPermissions(ctx *chetypes.DeployContext) (bool, error) {
	// Delete orphaned user-facing CRBs immediately on every reconcile so the che SA
	// loses excess permissions right after upgrade (not only at CheCluster deletion).
	orphanedCRBNames := []string{
		fmt.Sprintf(userCommonPermissionsTemplateName, ctx.CheCluster.Namespace),
		fmt.Sprintf(userDevWorkspacePermissionsTemplateName, ctx.CheCluster.Namespace),
	}
	for _, name := range orphanedCRBNames {
		if done, err := deploy.Delete(ctx, types.NamespacedName{Name: name}, &rbacv1.ClusterRoleBinding{}); !done {
			return false, err
		}
	}

	policies := map[string][]rbacv1.PolicyRule{
		fmt.Sprintf(cheSASpecificPermissionsTemplateName, ctx.CheCluster.Namespace): s.getCheSASpecificPolicies(),
	}

	for name, policy := range policies {
		if done, err := deploy.SyncClusterRoleToCluster(ctx, name, policy); !done {
			return false, err
		}

		if done, err := deploy.SyncClusterRoleBindingToCluster(ctx, name, constants.DefaultCheServiceAccountName, name); !done {
			return false, err
		}
	}

	for _, cheClusterRole := range ctx.CheCluster.Spec.Components.CheServer.ClusterRoles {
		cheClusterRole := strings.TrimSpace(cheClusterRole)
		if cheClusterRole != "" {
			if done, err := deploy.SyncClusterRoleBindingToCluster(ctx, cheClusterRole, constants.DefaultCheServiceAccountName, cheClusterRole); !done {
				return false, err
			}

			finalizer := s.getCRBFinalizerName(cheClusterRole)
			if err := deploy.AppendFinalizer(ctx, finalizer); err != nil {
				return false, err
			}
		}
	}

	// Delete abandoned CRBs
	for _, finalizer := range ctx.CheCluster.Finalizers {
		if strings.HasSuffix(finalizer, cheCRBFinalizerSuffix) {
			cheClusterRole := strings.TrimSuffix(finalizer, cheCRBFinalizerSuffix)
			if !util.Contains(ctx.CheCluster.Spec.Components.CheServer.ClusterRoles, cheClusterRole) {
				if done, err := deploy.Delete(ctx, types.NamespacedName{Name: cheClusterRole}, &rbacv1.ClusterRoleBinding{}); !done {
					return false, err
				}

				if err := deploy.DeleteFinalizer(ctx, finalizer); err != nil {
					return false, err
				}
			}
		}
	}

	return true, nil
}

func (s *CheServerReconciler) deletePermissions(ctx *chetypes.DeployContext) bool {
	names := []string{
		cheSASpecificPermissionsTemplateName,
	}

	done := true

	for _, nameTemplate := range names {
		name := fmt.Sprintf(nameTemplate, ctx.CheCluster.Namespace)
		if _, err := deploy.Delete(ctx, types.NamespacedName{Name: name}, &rbacv1.ClusterRole{}); err != nil {
			done = false
			logrus.Errorf("Failed to delete ClusterRole '%s', cause: %v", name, err)
		}

		if _, err := deploy.Delete(ctx, types.NamespacedName{Name: name}, &rbacv1.ClusterRoleBinding{}); err != nil {
			done = false
			logrus.Errorf("Failed to delete ClusterRoleBinding '%s', cause: %v", name, err)
		}
	}

	// Delete legacy user-facing CRBs (che-SA bindings) for upgrade compatibility.
	// Old operator installations will have orphaned ClusterRoleBindings that must be cleaned up.
	legacyCRBNames := []string{
		fmt.Sprintf(userCommonPermissionsTemplateName, ctx.CheCluster.Namespace),
		fmt.Sprintf(userDevWorkspacePermissionsTemplateName, ctx.CheCluster.Namespace),
	}
	for _, name := range legacyCRBNames {
		if _, err := deploy.Delete(ctx, types.NamespacedName{Name: name}, &rbacv1.ClusterRoleBinding{}); err != nil {
			done = false
			logrus.Errorf("Failed to delete ClusterRoleBinding '%s', cause: %v", name, err)
		}
	}

	for _, name := range ctx.CheCluster.Spec.Components.CheServer.ClusterRoles {
		name := strings.TrimSpace(name)
		if name != "" {
			if _, err := deploy.Delete(ctx, types.NamespacedName{Name: name}, &rbacv1.ClusterRoleBinding{}); err != nil {
				done = false
				logrus.Errorf("Failed to delete ClusterRoleBinding '%s', cause: %v", name, err)
			}

			// Removes any legacy CRB https://github.com/eclipse/che/issues/19506
			legacyName := ctx.CheCluster.Namespace + "-" + constants.DefaultCheServiceAccountName + "-" + name
			if _, err := deploy.Delete(ctx, types.NamespacedName{Name: legacyName}, &rbacv1.ClusterRoleBinding{}); err != nil {
				done = false
				logrus.Errorf("Failed to delete ClusterRoleBinding '%s', cause: %v", legacyName, err)
			}
		}
	}

	return done
}

func (s *CheServerReconciler) getCheSASpecificPolicies() []rbacv1.PolicyRule {
	k8sPolicies := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "create", "update", "list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "watch", "create"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"roles"},
			Verbs:     []string{"get", "create", "update"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"rolebindings"},
			Verbs:     []string{"get", "create", "update", "delete"},
		},
	}

	openshiftPolicies := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"project.openshift.io"},
			Resources: []string{"projectrequests"},
			Verbs:     []string{"create", "update"},
		},
		{
			APIGroups: []string{"project.openshift.io"},
			Resources: []string{"projects"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"user.openshift.io"},
			Resources: []string{"groups"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"authorization.openshift.io"},
			Resources: []string{"roles"},
			Verbs:     []string{"get", "create", "update"},
		},
		{
			APIGroups: []string{"authorization.openshift.io"},
			Resources: []string{"rolebindings"},
			Verbs:     []string{"get", "create", "update", "delete"},
		},
	}

	if infrastructure.IsOpenShift() {
		return append(k8sPolicies, openshiftPolicies...)
	}
	return k8sPolicies
}

// getDefaultUserClusterRoles returns the list of default user-facing ClusterRoles.
// NOTE: User-facing ClusterRoles have been removed from che-server RBAC management.
// This function now returns an empty slice; user ClusterRole reconciliation has been
// moved to pkg/deploy/rbac/ (T3).
func (s *CheServerReconciler) getDefaultUserClusterRoles(ctx *chetypes.DeployContext) []string {
	return []string{}
}
