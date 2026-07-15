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
	"fmt"
	"time"

	"github.com/eclipse-che/che-operator/pkg/common/chetypes"
	"github.com/eclipse-che/che-operator/pkg/common/constants"
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	"github.com/eclipse-che/che-operator/pkg/common/reconciler"
	"github.com/eclipse-che/che-operator/pkg/deploy"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	UserCommonClusterRoleFinalizerName       = "userCommonClusterRole.finalizers.che.eclipse.org"
	UserDevWorkspaceClusterRoleFinalizerName = "userDevWorkspaceClusterRole.finalizers.che.eclipse.org"
)

type UserClusterRolesReconciler struct {
	reconciler.Reconcilable
}

func NewUserClusterRolesReconciler() *UserClusterRolesReconciler {
	return &UserClusterRolesReconciler{}
}

func (u *UserClusterRolesReconciler) Reconcile(ctx *chetypes.DeployContext) (reconcile.Result, bool, error) {
	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, ctx.CheCluster.Namespace)
	if done, err := deploy.SyncClusterRoleToCluster(ctx, commonName, u.getUserCommonPolicies()); !done {
		return reconcile.Result{RequeueAfter: time.Second}, false, err
	}
	if err := deploy.AppendFinalizer(ctx, UserCommonClusterRoleFinalizerName); err != nil {
		return reconcile.Result{RequeueAfter: time.Second}, false, err
	}

	devworkspaceName := fmt.Sprintf(constants.UserDevWorkspacePermissionsTemplateName, ctx.CheCluster.Namespace)
	if done, err := deploy.SyncClusterRoleToCluster(ctx, devworkspaceName, u.getUserDevWorkspacePolicies()); !done {
		return reconcile.Result{RequeueAfter: time.Second}, false, err
	}
	if err := deploy.AppendFinalizer(ctx, UserDevWorkspaceClusterRoleFinalizerName); err != nil {
		return reconcile.Result{RequeueAfter: time.Second}, false, err
	}

	return reconcile.Result{}, true, nil
}

func (u *UserClusterRolesReconciler) Finalize(ctx *chetypes.DeployContext) bool {
	done := true

	commonName := fmt.Sprintf(constants.UserCommonPermissionsTemplateName, ctx.CheCluster.Namespace)
	if _, err := deploy.Delete(ctx, types.NamespacedName{Name: commonName}, &rbacv1.ClusterRole{}); err != nil {
		logrus.Errorf("Failed to delete ClusterRole '%s', cause: %v", commonName, err)
		done = false
	}
	if err := deploy.DeleteFinalizer(ctx, UserCommonClusterRoleFinalizerName); err != nil {
		logrus.Errorf("Failed to delete finalizer '%s', cause: %v", UserCommonClusterRoleFinalizerName, err)
		done = false
	}

	devworkspaceName := fmt.Sprintf(constants.UserDevWorkspacePermissionsTemplateName, ctx.CheCluster.Namespace)
	if _, err := deploy.Delete(ctx, types.NamespacedName{Name: devworkspaceName}, &rbacv1.ClusterRole{}); err != nil {
		logrus.Errorf("Failed to delete ClusterRole '%s', cause: %v", devworkspaceName, err)
		done = false
	}
	if err := deploy.DeleteFinalizer(ctx, UserDevWorkspaceClusterRoleFinalizerName); err != nil {
		logrus.Errorf("Failed to delete finalizer '%s', cause: %v", UserDevWorkspaceClusterRoleFinalizerName, err)
		done = false
	}

	return done
}

func (u *UserClusterRolesReconciler) getUserCommonPolicies() []rbacv1.PolicyRule {
	k8sPolicies := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods/exec"},
			Verbs:     []string{"get", "create"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods/log"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods/portforward"},
			Verbs:     []string{"get", "list", "create"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"persistentvolumeclaims"},
			Verbs:     []string{"get", "list", "watch", "create", "delete", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch", "create", "delete", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "create", "delete", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "create", "patch", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"replicasets"},
			Verbs:     []string{"get", "list", "patch", "delete"},
		},
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs:     []string{"get", "list", "watch", "create", "delete"},
		},
		{
			APIGroups: []string{"metrics.k8s.io"},
			Resources: []string{"pods", "nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"watch", "list"},
		},
	}

	openshiftPolicies := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"route.openshift.io"},
			Resources: []string{"routes"},
			Verbs:     []string{"get", "list", "create", "delete"},
		},
		{
			APIGroups: []string{"project.openshift.io"},
			Resources: []string{"projects"},
			Verbs:     []string{"get"},
		},
	}

	if infrastructure.IsOpenShift() {
		return append(k8sPolicies, openshiftPolicies...)
	}
	return k8sPolicies
}

func (u *UserClusterRolesReconciler) getUserDevWorkspacePolicies() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{"workspace.devfile.io"},
			Resources: []string{"devworkspaces", "devworkspacetemplates"},
			Verbs:     []string{"get", "create", "delete", "list", "update", "patch", "watch"},
		},
	}
}
