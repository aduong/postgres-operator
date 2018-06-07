package pvc

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
	"bytes"
	"encoding/json"
	"time"

	log "github.com/Sirupsen/logrus"
	crv1 "github.com/crunchydata/postgres-operator/apis/cr/v1"
	"github.com/crunchydata/postgres-operator/kubeapi"
	"github.com/crunchydata/postgres-operator/operator"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// TemplateFields ...
type TemplateFields struct {
	Name         string
	AccessMode   string
	ClusterName  string
	Size         string
	StorageClass string
}

// CreatePVC create a pvc
func CreatePVC(clientset *kubernetes.Clientset, storageSpec *crv1.PgStorageSpec, pvcName, clusterName, namespace string) (string, error) {
	var err error

	switch storageSpec.StorageType {
	case "":
		log.Debug("StorageType is empty")
	case "emptydir":
		log.Debug("StorageType is emptydir")
	case "existing":
		log.Debug("StorageType is existing")
		pvcName = storageSpec.Name
	case "create", "dynamic":
		log.Debug("StorageType is create")
		log.Debugf("Name=%s Size=%s AccessMode=%s\n",
			pvcName, storageSpec.AccessMode, storageSpec.Size)
		err = Create(clientset, pvcName, clusterName, storageSpec.AccessMode, storageSpec.Size, storageSpec.StorageType, storageSpec.StorageClass, namespace)
		if err != nil {
			log.WithError(err).Error("error in pvc create")
			return pvcName, err
		}
		log.Infof("created PVC %s in namespace %s", pvcName, namespace)
	}

	return pvcName, err
}

// Create a pvc
func Create(clientset *kubernetes.Clientset, name, clusterName string, accessMode string, pvcSize string, storageType string, storageClass string, namespace string) error {
	log.Debug("in createPVC")
	var doc2 bytes.Buffer
	var err error

	pvcFields := TemplateFields{
		Name:         name,
		AccessMode:   accessMode,
		StorageClass: storageClass,
		ClusterName:  clusterName,
		Size:         pvcSize,
	}

	if storageType == "dynamic" {
		log.Debug("using dynamic PVC template")
		err = operator.PVCStorageClassTemplate.Execute(&doc2, pvcFields)
	} else {
		err = operator.PVCTemplate.Execute(&doc2, pvcFields)
	}
	if err != nil {
		log.Error("error in pvc create exec" + err.Error())
		return err
	}
	pvcDocString := doc2.String()
	log.Debug(pvcDocString)

	//template name is lspvc-pod.json
	//create lspvc pod
	newpvc := v1.PersistentVolumeClaim{}
	err = json.Unmarshal(doc2.Bytes(), &newpvc)
	if err != nil {
		log.Error("error unmarshalling json into PVC " + err.Error())
		return err
	}

	err = kubeapi.CreatePVC(clientset, &newpvc, namespace)
	if err != nil {
		return err
	}

	//TODO replace sleep with proper wait
	time.Sleep(3000 * time.Millisecond)
	return nil

}

// Delete a pvc
func Delete(clientset *kubernetes.Clientset, name string, namespace string) error {
	log.Debug("in pvc.Delete")
	var err error
	var found bool
	var pvc *v1.PersistentVolumeClaim

	//see if the PVC exists
	pvc, found, err = kubeapi.GetPVC(clientset, name, namespace)
	if err != nil || !found {
		log.Infof("PVC %s not found, will not attempt delete", name)
		return nil
	}

	log.Infof("PVC %s found: %v", pvc.Name, pvc)
	//if pgremove = true remove it
	if pvc.ObjectMeta.Labels["pgremove"] == "true" {
		log.Info("pgremove is true on this pvc")
		log.Debugf("delete PVC %v in namespace %v", name, namespace)
		err = kubeapi.DeletePVC(clientset, name, namespace)
		if err != nil {
			return err
		}
	}

	return nil

}

// Exists test to see if pvc exists
func Exists(clientset *kubernetes.Clientset, name string, namespace string) bool {
	_, found, _ := kubeapi.GetPVC(clientset, name, namespace)

	return found
}
