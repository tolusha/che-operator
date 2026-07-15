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

package usernamespace

import (
	"github.com/eclipse-che/che-operator/pkg/common/infrastructure"
	defaults "github.com/eclipse-che/che-operator/pkg/common/operator-defaults"
	"github.com/eclipse-che/che-operator/pkg/common/test"
	userv1 "github.com/openshift/api/user/v1"
	controllerv1alpha1 "github.com/devfile/devworkspace-operator/apis/controller/v1alpha1"
	chev1alpha1 "github.com/che-incubator/kubernetes-image-puller-operator/api/v1alpha1"
	chev2 "github.com/eclipse-che/che-operator/api/v2"
	console "github.com/openshift/api/console/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	projectv1 "github.com/openshift/api/project/v1"
	templatev1 "github.com/openshift/api/template/v1"
	securityv1 "github.com/openshift/api/security/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func init() {
	test.EnableTestMode()

	infrastructure.InitializeForTesting(infrastructure.OpenShiftV4)
	defaults.InitializeForTesting("../../config/manager/manager.yaml")
}

// newSchemeWithUserv1 creates a scheme that includes all standard Che types plus
// userv1 (OpenShift Group), making Group objects available across package tests.
func newSchemeWithUserv1() *runtime.Scheme {
	s := runtime.NewScheme()

	// Standard k8s types
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = batchv1.AddToScheme(s)

	// OpenShift types (including userv1 for Group objects)
	_ = userv1.AddToScheme(s)
	_ = oauthv1.AddToScheme(s)
	_ = configv1.AddToScheme(s)
	_ = routev1.AddToScheme(s)
	_ = templatev1.AddToScheme(s)
	_ = projectv1.AddToScheme(s)
	_ = securityv1.AddToScheme(s)
	_ = console.AddToScheme(s)

	// Che types
	_ = chev2.AddToScheme(s)
	_ = chev1alpha1.AddToScheme(s)
	_ = controllerv1alpha1.AddToScheme(s)
	_ = monitoringv1.AddToScheme(s)

	return s
}
