package util

/*
 Copyright 2017-2018 Crunchy Data Solutions, Inc.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

import (
	"math/rand"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	crv1 "github.com/crunchydata/postgres-operator/apis/cr/v1"
	"github.com/crunchydata/postgres-operator/kubeapi"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const lowercharset = "abcdefghijklmnopqrstuvwxyz"

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

// CreateDatabaseSecrets create pgroot, pgprimary, and pguser secrets.
// Updates the passed in Pgcluster with secret names, user names, and passwords.
// Does not patch with any generated passwords as those are stored in secrets.
func CreateDatabaseSecrets(
	clientset *kubernetes.Clientset, restclient *rest.RESTClient, cl *crv1.Pgcluster, namespace string) (retErr error) {

	cluster := cl.Spec.Name

	rootUser := "postgres"
	rootParams := createSecretParams{
		clientset:  clientset,
		restClient: restclient,
		cluster:    cluster,
		namespace:  namespace,

		secretNamePath:    "/spec/rootsecretname",
		secretName:        &cl.Spec.RootSecretName,
		defaultSecretName: cluster + crv1.RootSecretSuffix,

		user:     &rootUser,
		password: &cl.Spec.RootPassword,
	}
	if err := rootParams.createSecret(); err != nil {
		retErr = err
	}

	primaryUser := "primaryuser"
	primaryParams := createSecretParams{
		clientset:  clientset,
		restClient: restclient,
		cluster:    cluster,
		namespace:  namespace,

		secretNamePath:    "/spec/primarysecretname",
		secretName:        &cl.Spec.PrimarySecretName,
		defaultSecretName: cluster + crv1.PrimarySecretSuffix,

		user:     &primaryUser,
		password: &cl.Spec.PrimaryPassword,
	}
	if err := primaryParams.createSecret(); err != nil {
		retErr = err
	}

	user := "testuser" // default, may be overridden
	userParams := createSecretParams{
		clientset:  clientset,
		restClient: restclient,
		cluster:    cluster,
		namespace:  namespace,

		secretNamePath:    "/spec/usersecretname",
		secretName:        &cl.Spec.UserSecretName,
		defaultSecretName: cluster + crv1.UserSecretSuffix(user),

		userPath:    "/spec/user",
		user:        &cl.Spec.User,
		defaultUser: user,

		password: &cl.Spec.Password,
	}
	if err := userParams.createSecret(); err != nil {
		retErr = err
	}

	return
}

type createSecretParams struct {
	clientset  *kubernetes.Clientset
	restClient *rest.RESTClient
	cluster    string
	namespace  string

	secretNamePath    string
	secretName        *string
	defaultSecretName string

	userPath    string
	user        *string
	defaultUser string

	password *string
}

// Creates secrets from secret name, user, and password, while ensuring that those values are
// updated on the pgcluster object. If secret name or user are absent, then those are updated
// with their defaults and the pgcluster is patched according to the provided paths.
// If password is absent, then it's generated.
func (p *createSecretParams) createSecret() (retErr error) {
	l := p.log()

	if *p.user == "" && p.defaultUser != "" {
		*p.user = p.defaultUser
		if err := p.patch(p.userPath, *p.user); err != nil {
			retErr = err
		}
	}

	if *p.secretName == "" && p.defaultSecretName != "" {
		*p.secretName = p.defaultSecretName
		if err := p.patch(p.secretNamePath, *p.secretName); err != nil {
			retErr = err
		}
	}

	l = l.WithField("secretName", *p.secretName)

	if *p.password == "" {
		*p.password = GeneratePassword(10)
		// intentionally not patching the pgcluster to have password in plaintext
	} else {
		l.Debug("using user specified password")
	}

	err := CreateSecret(p.clientset, p.cluster, *p.secretName, *p.user, *p.password, p.namespace)
	if err != nil {
		retErr = err
		l.WithError(err).Error("error creating secret")
	}

	return
}

func (p *createSecretParams) patch(path, value string) error {
	if err := Patch(p.restClient, path, value, crv1.PgclusterResourcePlural, p.cluster, p.namespace); err != nil {
		p.log().WithError(err).Error("error patching cluster")
		return err
	}
	return nil
}

func (p *createSecretParams) log() *log.Entry {
	return log.WithField("namespace", p.namespace).WithField("cluster", p.cluster)
}

// CreateSecret create the secret, user, and primary secrets
func CreateSecret(clientset *kubernetes.Clientset, db, secretName, username, password, namespace string) error {

	var enUsername = username

	secret := v1.Secret{}

	secret.Name = secretName
	secret.ObjectMeta.Labels = make(map[string]string)
	secret.ObjectMeta.Labels["pg-database"] = db
	secret.Data = make(map[string][]byte)
	secret.Data["username"] = []byte(enUsername)
	secret.Data["password"] = []byte(password)

	err := kubeapi.CreateSecret(clientset, &secret, namespace)

	return err

}

// stringWithCharset returns a generated string value
func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// GeneratePassword generate a password of a given length
func GeneratePassword(length int) string {
	return stringWithCharset(length, charset)
}

// GenerateRandString generate a rand lowercase string of a given length
func GenerateRandString(length int) string {
	return stringWithCharset(length, lowercharset)
}

// DeleteDatabaseSecrets delete secrets that match pg-database=somecluster
func DeleteDatabaseSecrets(clientset *kubernetes.Clientset, db, namespace string) {
	//get all that match pg-database=db
	selector := "pg-database=" + db
	secrets, err := kubeapi.GetSecrets(clientset, selector, namespace)
	if err != nil {
		return
	}

	for _, s := range secrets.Items {
		kubeapi.DeleteSecret(clientset, s.ObjectMeta.Name, namespace)
	}
}

// GetPasswordFromSecret will fetch the username, password from a user secret
func GetPasswordFromSecret(clientset *kubernetes.Clientset, namespace string, secretName string) (string, string, error) {

	if clientset == nil {
		log.Errorln("clientset is nil")
	}
	log.Infoln("namespace=" + namespace)
	log.Infoln("secretName=" + secretName)

	secret, found, err := kubeapi.GetSecret(clientset, secretName, namespace)
	if !found || err != nil {
		return "", "", err
	}

	return string(secret.Data["username"][:]), string(secret.Data["password"][:]), err

}

// CopySecrets will copy a secret to another secret
func CopySecrets(clientset *kubernetes.Clientset, namespace string, fromCluster, toCluster string) error {

	log.Debug("CopySecrets " + fromCluster + " to " + toCluster)
	selector := "pg-database=" + fromCluster

	secrets, err := kubeapi.GetSecrets(clientset, selector, namespace)
	if err != nil {
		return err
	}

	for _, s := range secrets.Items {
		log.Debug("found secret : " + s.ObjectMeta.Name)
		secret := v1.Secret{}
		secret.Name = strings.Replace(s.ObjectMeta.Name, fromCluster, toCluster, 1)
		secret.ObjectMeta.Labels = make(map[string]string)
		secret.ObjectMeta.Labels["pg-database"] = toCluster
		secret.Data = make(map[string][]byte)
		secret.Data["username"] = s.Data["username"][:]
		secret.Data["password"] = s.Data["password"][:]

		kubeapi.CreateSecret(clientset, &secret, namespace)

	}
	return err

}

// CreateUserSecret will create a new secret holding a user credential
func CreateUserSecret(clientset *kubernetes.Clientset, clustername, username, password, namespace string) error {

	var err error

	secretName := clustername + "-" + username + "-secret"
	var enPassword = GeneratePassword(10)
	if password != "" {
		log.Debug("using user specified password for secret " + secretName)
		enPassword = password
	}
	err = CreateSecret(clientset, clustername, secretName, username, enPassword, namespace)
	if err != nil {
		log.Error("error creating secret" + err.Error())
	}

	return err
}

// UpdateUserSecret updates a user secret with a new password
func UpdateUserSecret(clientset *kubernetes.Clientset, clustername, username, password, namespace string) error {

	var err error

	secretName := clustername + "-" + username + "-secret"

	//delete current secret
	err = kubeapi.DeleteSecret(clientset, secretName, namespace)
	if err == nil {
		//create secret with updated password
		err = CreateUserSecret(clientset, clustername, username, password, namespace)
		if err != nil {
			log.Error("UpdateUserSecret error creating secret" + err.Error())
		} else {
			log.Debug("created secret " + secretName)
		}
	}

	return err
}

// DeleteUserSecret will delete a user secret
func DeleteUserSecret(clientset *kubernetes.Clientset, clustername, username, namespace string) error {
	//delete current secret
	secretName := clustername + "-" + username + "-secret"

	err := kubeapi.DeleteSecret(clientset, secretName, namespace)
	return err
}
