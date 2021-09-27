# API REST (para conocer el estado de ELK)

## USO de CAT

Enlace a la documentación oficial https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html

> El uso de la **letra "v"** al final de la consulta es para activar la verbosidad, esto hace que salgan el nombre de las columnas.

Comando para saber la salud 

```bash
curl -XGET http://localhost:9200/_cat/health?v
```

Ver información del nodo master

```bash
curl -XGET http://localhost:9200/_cat/master?v
```

Ver los índices. (IMPORTANTE)

```BASH
curl -XGET http://localhost:9200/_cat/indices?v
```

Ver información de los shards

```bash
curl -XGET http://localhost:9200/_cat/shards?v
```

