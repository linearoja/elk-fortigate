# Manual - Instalación en Ubuntu Server 20.04 LTS

## Especificaciones

* Ubuntu 20.04 full actualizado a la fecha de 24/09/2021



# Pasos

### Instalar Elasticsearch

Ir a la pagina https://www.elastic.co/es/downloads/elasticsearch#ga-release y copiar el enlace DEB

Crear un carpeta llamada elk y descargarlo

```bash
$ mkdir elk
$ cd elk
$ wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.15.0-amd64.deb
```

Desempaquetar e instalar el .deb

```bash
$ sudo dpkg -i elasticsearch-7.15.0-amd64.deb
```

Ver estatus de servicio e inicializar. Debe aparecer **activo** al final.

```bash
$ sudo systemctl status elasticsearch
$ sudo systemctl enable elasticsearch
$ sudo systemctl start elasticsearch
$ sudo systemctl status elasticsearch
```

Para ver log del inicio del servicio

```bash
$ sudo tail -f /var/log/elasticsearch/elasticsearch.log
```

Para ver que el índice este bien montado

```bash
curl -XGET localhost:9200
{
  "name" : "elk01",
  "cluster_name" : "clusterk01",
  "cluster_uuid" : "ETUNEsLmTjmHvnqa1-XVnw",
  "version" : {
    "number" : "7.15.0",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "79d65f6e357953a5b3cbcc5e2c7c21073d89aa29",
    "build_date" : "2021-09-16T03:05:29.143308416Z",
    "build_snapshot" : false,
    "lucene_version" : "8.9.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
```

Para ver que esta escuchando por ese puerto. Hasta el momento todo OK.

```bash
$ sudo lsof -i:9200
COMMAND   PID          USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
java    14476 elasticsearch  298u  IPv6  43279      0t0  TCP ip6-localhost:9200 (LISTEN)
java    14476 elasticsearch  299u  IPv6  43280      0t0  TCP localhost:9200 (LISTEN)
```

Descomentar y Cambiar el nombre del Cluster.

```bash
$ sudo vim /etc/elasticsearch/elasticsearch.yml
```

```
cluster.name: clusterk01
```

```bash
$ sudo systemctl restart elasticsearch
```

Editar y cambiarle el tamaño de la RAM que usara. En este ejemplo puse mínimo 2GB y máximo 3GB.

```bash
$ sudo vim /etc/elasticsearch/jvm.options
```

```
-Xms2g
-Xmx3g
```

```bash
$ sudo systemctl restart elasticsearch
```



### Instalar Logstash

Si quieres leer -> https://www.elastic.co/guide/en/logstash/current/installing-logstash.html

Ir a la pagina https://www.elastic.co/es/downloads/logstash y copiar el enlace DEB. En la misma carpeta.

```bash
$ wget https://artifacts.elastic.co/downloads/logstash/logstash-7.15.0-amd64.deb
```

Desempaquetar e instalar el .deb

```bash
$ sudo dpkg -i logstash-7.15.0-amd64.deb
```

Ver estatus de servicio e inicializar. Debe aparecer **activo** al final.

```bash
$ sudo systemctl status logstash
$ sudo systemctl enable logstash
$ sudo systemctl start logstash
$ sudo systemctl status logstash
```

Editar y cambiarle el tamaño de la RAM que usara. En este ejemplo puse mínimo 3GB y máximo 4GB.

```
sudo vim /etc/logstash/jvm.options
```

#### Ficheros de configuracion .conf.d/

Copy-paste tomado de aquí https://www.elastic.co/guide/en/logstash/current/advanced-pipeline.html

Agregamos un fichero de configuración

Agregamos un archivo de configuracion de entrada

```bash
$ vim /etc/logstash/conf.d/01_inputs.conf
```

```
input {
    beats {
        port => "5044"
    }
}
```

Agregamos un archivo de configuracion de filtro

```bash
$ vim /etc/logstash/conf.d/02_forigate.conf
```

```
filter {

}
```

Agregamos un archivo de configuracion de salida

```bash
$ vim /etc/logstash/conf.d/99_outputs.conf
```

```
output {
    elasticsearch {
        hosts => [ "localhost:9200" ]
    }
}
```

##### Validar los archivos de configuración

Creamos un archivo `test.sh` en la ruta `/etc/logstash`.

```
cd  --config.test_and_exit -f /etc/logstash/conf.d/
```

```bash
chmod +x test.ssh
```
```bash
cd /etc/logstash/
./test.ssh
```

```bash
...
[INFO ] 2021-09-24 20:40:23.825 [LogStash::Runner] runner - Using config.test_and_exit mode. Config Validation Result: OK. Exiting Logstash
```

Al final aparece un linea que dice **Result OK**, que quiere decir que todo esta bien.

##### Log inicializacion de servicio

Ruta donde estan los log `/var/log/logstash/`. El que tenemos que monitorea es el siguiente:

```bash
tail -f /var/log/logstash/logstash-plain.log
```

Iniciamos el servicio o poder ver que va saliendo.

##### TCPdump

Comando para saber desde que ip de origen viene el trafico del Fortigate.

```bash
$ sudo tcpdump -vv udp port 514
```

Comando para ver lo log en grudo

```bash
sudo tcpdump -vv host 192.168.2.1 and udp port 9005 -A
```



### Instalar Kibana

Ir a la pagina https://www.elastic.co/es/downloads/kibana y copiar el enlace DEB. En la misma carpeta.

```bash
$ wget https://artifacts.elastic.co/downloads/kibana/kibana-7.15.0-amd64.deb
```

Desempaquetar e instalar el .deb

```bash
$ sudo dpkg -i kibana-7.15.0-amd64.deb
```

Ver estatus de servicio e inicializar. Debe aparecer **activo** al final.

```bash
$ sudo systemctl status kibana
$ sudo systemctl enable kibana
$ sudo systemctl start kibana
$ sudo systemctl status kibana
```

Se accede al http://[IP]:5601

### Configuración de .conf.d/ para Fortigate

* **input:** Configuración del output tomando gracias al trabajo de **georgezpt** https://github.com/georgezpt/ELK/blob/main/Logstash/conf.d/01_inputs.conf

  ```
  input {
      beats {
          port => "5044"
      }
  }
  
  
  input {
      udp {
          port => "9005"
          type => "firewall"
      }
  }
  ```

  

* **filter:** Configuración del output tomando gracias al trabajo de **georgezpt** https://github.com/georgezpt/ELK/blob/main/Logstash/conf.d/06_fortigate.conf

  ```
  filter {
          if [type] == "firewall" {
  
                  mutate {
                          add_tag => ["fortigate"]
                  }
  
                  grok {
                          break_on_match => false
                          match => [ "message", "%{SYSLOG5424PRI:syslog_index}%{GREEDYDATA:message}" ]
                          overwrite => [ "message" ]
                          tag_on_failure => [ "failure_grok_fortigate" ]
                  }
  
                  kv { }
  
                  if [msg] {
                          mutate {
                                  replace => [ "message", "%{msg}" ]
                          }
                  }
  
                  mutate {
                          convert => { "duration" => "integer" }
                          convert => { "rcvdbyte" => "integer" }
                          convert => { "rcvdpkt" => "integer" }
                          convert => { "sentbyte" => "integer" }
                          convert => { "sentpkt" => "integer" }
                          convert => { "cpu" => "integer" }
                          convert => { "disk" => "integer" }
                          convert => { "disklograte" => "integer" }
                          convert => { "fazlograte" => "integer" }
                          convert => { "mem" => "integer" }
                          convert => { "totalsession" => "integer" }
                  }
  
                  mutate {
                          add_field => [ "fgtdatetime", "%{date} %{time}" ]
                          add_field => [ "loglevel", "%{level}" ]
                          replace => [ "fortigate_type", "%{type}" ]
                          replace => [ "fortigate_subtype", "%{subtype}" ]
                          remove_field => [ "msg", "message", "date", "time", "eventtime" ]
                  }
  
                  date {
                          match => [ "fgtdatetime", "YYYY-MM-dd HH:mm:ss" ]
                          locale => "en"
                          timezone => "America/Panama"
                          remove_field => [ "fgtdatetime" ]
                  }
  
                  geoip {
                          source => "srcip"
                          target => "geosrcip"
                          add_field => [ "[geosrcip][coordinates]", "%{[geosrcip][longitude]}" ]
                          add_field => [ "[geosrcip][coordinates]", "%{[geosrcip][latitude]}" ]
                  }
  
                  geoip {
                          source => "dstip"
                          target => "geodstip"
                          add_field => [ "[geodstip][coordinates]", "%{[geodstip][longitude]}" ]
                          add_field => [ "[geodstip][coordinates]", "%{[geodstip][latitude]}" ]
                  }
  
                  mutate {
                          convert => [ "[geoip][coordinates]", "float" ]
                  }
  
          }
  }
  ```



* **Output:** Configuración del output tomando gracias al trabajo de **georgezpt** https://github.com/georgezpt/ELK/blob/main/Logstash/conf.d/99_outputs.conf

  ```
  output {
          if [host] == "192.168.2.1" {
                  elasticsearch {
                          hosts => ["http://localhost:9200"]
                          index => "fortinet-%{+YYYY.MM.dd}"
                  }
          }
          else {
                  elasticsearch {
                          hosts => ["http://localhost:9200"]
                          index => "%{[@metadata][beat]}-%{[@metadata][version]}"
                  }
          }
  }
  ```

  

### Habilitar seguridad

Leer https://www.elastic.co/guide/en/elasticsearch/reference/7.15/configuring-stack-security.html?blade=kibanasecuritymessage

https://www.elastic.co/guide/en/elasticsearch/reference/7.15/security-minimal-setup.html

### Comando en Fortigate

```
config log syslogd setting
    set status enable
    set format default
    set server "10.10.0.8"
    set port 9005
end
```

