package dfservice

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
	"database/sql"
	"errors"
	//"fmt"
	log "github.com/Sirupsen/logrus"
	crv1 "github.com/crunchydata/postgres-operator/apis/cr/v1"
	"github.com/crunchydata/postgres-operator/apiserver"
	msgs "github.com/crunchydata/postgres-operator/apiservermsgs"
	"github.com/crunchydata/postgres-operator/kubeapi"
	"k8s.io/client-go/kubernetes"

	//"github.com/crunchydata/postgres-operator/util"
	_ "github.com/lib/pq"
	//"github.com/spf13/viper"
	"k8s.io/api/core/v1"
	//meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"k8s.io/apimachinery/pkg/util/validation"
	//"strconv"
	//"strings"
	//"time"
)

func DfCluster(name, selector string) msgs.DfResponse {
	var err error

	response := msgs.DfResponse{}
	response.Results = make([]msgs.DfDetail, 0)
	response.Status = msgs.Status{Code: msgs.Ok, Msg: ""}

	log.Debug("selector is " + selector)
	if selector == "" && name == "all" {
		log.Debug("selector is empty and name is all")
	} else {
		if selector == "" {
			selector = "name=" + name
		}
	}

	//get a list of matching clusters
	clusterList := crv1.PgclusterList{}
	err = kubeapi.GetpgclustersBySelector(apiserver.RESTClient, &clusterList, selector, apiserver.Namespace)

	if err != nil {
		response.Status.Code = msgs.Error
		response.Status.Msg = err.Error()
		return response
	}

	//loop thru each cluster

	log.Debug("clusters found len is %d\n", len(clusterList.Items))

	for _, c := range clusterList.Items {

		services, err := getServices(c.Spec.Name)
		if err != nil {
			response.Status.Code = msgs.Error
			response.Status.Msg = err.Error()
			return response
		}

		//for each service get the database size and append to results
		for svcName, svcIP := range services {
			result := msgs.DfDetail{}
			//result.Name = c.Name
			result.Name = svcName
			result.Working = true

			pgSizePretty, pgSize, err := getPGSize(c.Spec.Port, svcIP, "postgres", c.Spec.Name)
			log.Infof("svcName=%s pgSize=%d pgSize=%s cluster=%s", svcName, pgSize, pgSizePretty)
			if err != nil {
				response.Status.Code = msgs.Error
				response.Status.Msg = err.Error()
				return response
			}
			result.PGSize = pgSizePretty
			result.ClaimSize = getClaimCapacity(apiserver.Clientset, c.Spec.Name+"-pvc")
			response.Results = append(response.Results, result)
		}

	}

	return response
}

// getPrimarySecret get only the primary postgres secret
func getPrimarySecret(clusterName string) (string, string, error) {

	selector := "pgpool!=true,pg-database=" + clusterName

	secrets, err := kubeapi.GetSecrets(apiserver.Clientset, selector, apiserver.Namespace)
	if err != nil {
		return "", "", err
	}

	secretName := clusterName + "-postgres-secret"
	for _, s := range secrets.Items {
		if s.Name == secretName {
			username := string(s.Data["username"][:])
			password := string(s.Data["password"][:])
			return username, password, err
		}

	}

	return "", "", errors.New("secret " + secretName + " not found")
}

// getPrimaryService returns the service IP addresses
func getServices(clusterName string) (map[string]string, error) {

	output := make(map[string]string, 0)
	selector := "pg-cluster=" + clusterName

	services, err := kubeapi.GetServices(apiserver.Clientset, selector, apiserver.Namespace)
	if err != nil {
		return output, err
	}

	for _, p := range services.Items {
		output[p.Name] = p.Spec.ClusterIP
	}

	return output, err
}

// getPGSize clusterName returns sizestring, error
func getPGSize(port, host, databaseName, clusterName string) (string, int, error) {
	var dbsizePretty string
	var dbsize int
	var conn *sql.DB

	username, password, err := getPrimarySecret(clusterName)
	if err != nil {
		log.Error(err.Error())
		return dbsizePretty, dbsize, err
	}
	log.Info("username=" + username + " password=" + password)

	conn, err = sql.Open("postgres", "sslmode=disable user="+username+" host="+host+" port="+port+" dbname="+databaseName+" password="+password)
	if err != nil {
		log.Error(err.Error())
		return dbsizePretty, dbsize, err
	}

	var rows *sql.Rows

	rows, err = conn.Query("select pg_size_pretty(sum(pg_database_size(pg_database.datname))), sum(pg_database_size(pg_database.datname)) from pg_database")
	if err != nil {
		log.Error(err.Error())
		return dbsizePretty, dbsize, err
	}

	defer func() {
		if conn != nil {
			conn.Close()
		}
		if rows != nil {
			rows.Close()
		}
	}()
	for rows.Next() {
		if err = rows.Scan(&dbsizePretty, &dbsize); err != nil {
			log.Error(err.Error())
			return "", 0, err
		}
		log.Debug("returned %s %d\n", dbsizePretty, dbsize)
		return dbsizePretty, dbsize, err
	}

	return dbsizePretty, dbsize, err

}

func getClaimCapacity(clientset *kubernetes.Clientset, claimname string) string {
	pvc, found, err := kubeapi.GetPVC(clientset, claimname, "demo")
	if err != nil {
		return "error"
	}
	if !found {
		log.Error("not found")
		return "not found"
	}
	//fmt.Printf("storage cap is %s\n", pvc.Status.Capacity[v1.ResourceStorage])
	qty := pvc.Status.Capacity[v1.ResourceStorage]
	log.Debugf("storage cap string value %s\n", qty.String())

	return qty.String()

}