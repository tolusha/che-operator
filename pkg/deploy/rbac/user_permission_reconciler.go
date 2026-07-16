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
	"fmt"

	chev2 "github.com/eclipse-che/che-operator/api/v2"
	"github.com/eclipse-che/che-operator/pkg/common/constants"
	k8sclient "github.com/eclipse-che/che-operator/pkg/common/k8s-client"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// UserPermissionReconciler is a controller-runtime controller that watches CheCluster
// objects and reconciles user permissions (RoleBindings) in workspace namespaces.
type UserPermissionReconciler struct {
	client        client.Client
	scheme        *runtime.Scheme
	groupResolver GroupResolver
}

// NewUserPermissionReconciler creates a new UserPermissionReconciler.
func NewUserPermissionReconciler(client client.Client, scheme *runtime.Scheme, groupResolver GroupResolver) *UserPermissionReconciler {
	return &UserPermissionReconciler{
		client:        client,
		scheme:        scheme,
		groupResolver: groupResolver,
	}
}

// SetupWithManager registers the controller with the manager, watching CheCluster objects.
func (r *UserPermissionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&chev2.CheCluster{}).
		Complete(r)
}

// Reconcile fetches the CheCluster by req.NamespacedName, lists all workspace namespaces,
// and calls SyncPermissionsForNamespace for each one.
func (r *UserPermissionReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	cheCluster := &chev2.CheCluster{}
	if err := r.client.Get(ctx, req.NamespacedName, cheCluster); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// List all workspace namespaces (those labeled with app.kubernetes.io/component=workspaces-namespace).
	nsList := &corev1.NamespaceList{}
	if err := r.client.List(ctx, nsList, client.MatchingLabels{
		"app.kubernetes.io/component": "workspaces-namespace",
	}); err != nil {
		return reconcile.Result{}, err
	}

	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if err := r.SyncPermissionsForNamespace(ctx, cheCluster, ns.Name); err != nil {
			logrus.Errorf("Failed to sync user permissions for namespace '%s': %v", ns.Name, err)
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// SyncPermissionsForNamespace runs the per-namespace permission sync for one namespace.
// It resolves the namespace owner, evaluates IsUserPermitted, and applies or removes
// the appropriate RoleBindings.
func (r *UserPermissionReconciler) SyncPermissionsForNamespace(ctx context.Context, cheCluster *chev2.CheCluster, namespace string) error {
	// (1) Resolve namespace owner username from namespace annotation.
	ns := &corev1.Namespace{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	annotations := ns.GetAnnotations()
	username := ""
	if annotations != nil {
		username = annotations["che.eclipse.org/username"]
	}

	// (2) If username is empty, return nil (not a user workspace).
	if username == "" {
		return nil
	}

	// (3) Evaluate IsUserPermitted — dereference pointer if non-nil, use zero value if nil.
	var policy chev2.AdvancedAuthorization
	if cheCluster.Spec.Networking.Auth.AdvancedAuthorization != nil {
		policy = *cheCluster.Spec.Networking.Auth.AdvancedAuthorization
	}

	permitted, err := IsUserPermitted(ctx, username, r.groupResolver, policy)
	if err != nil {
		return err
	}

	// Determine ClusterRoles to bind/remove.
	var clusterRoles []string
	if cheCluster.Spec.DevEnvironments.User != nil {
		clusterRoles = cheCluster.Spec.DevEnvironments.User.ClusterRoles
	}

	clientWrapper := k8sclient.NewK8sClient(r.client, r.scheme)

	for _, clusterRoleName := range clusterRoles {
		rbName := fmt.Sprintf("che-user-permission-%s", clusterRoleName)

		if permitted {
			// (4) Apply RoleBinding binding username to the ClusterRole.
			rb := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{
					Kind:       "RoleBinding",
					APIVersion: rbacv1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      rbName,
					Namespace: namespace,
					Labels:    map[string]string{constants.KubernetesPartOfLabelKey: constants.CheEclipseOrg},
				},
				RoleRef: rbacv1.RoleRef{
					Name:     clusterRoleName,
					Kind:     "ClusterRole",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:     rbacv1.UserKind,
						APIGroup: "rbac.authorization.k8s.io",
						Name:     username,
					},
				},
			}

			if err := clientWrapper.Sync(ctx, rb); err != nil {
				return err
			}
		} else {
			// (5) Delete the RoleBinding from namespace.
			if err := clientWrapper.DeleteByKeyIgnoreNotFound(
				ctx,
				types.NamespacedName{Name: rbName, Namespace: namespace},
				&rbacv1.RoleBinding{},
			); err != nil {
				return err
			}
		}
	}

	return nil
}
