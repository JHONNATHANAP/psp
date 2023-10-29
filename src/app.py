import json
from flask import Flask, jsonify, request
from sqlalchemy import create_engine, MetaData, Table, select
import os

app = Flask(__name__)

# obtener la URL de la base de datos desde una variable de ambiente
db_url = os.environ.get('DB_URI')

# crear una instancia de engine de SQLAlchemy
engine = create_engine(db_url, echo=True, pool_pre_ping=True)

# crear una instancia de MetaData de SQLAlchemy
metadata = MetaData()

# cargar las tablas de la base de datos
metadata.reflect(bind=engine)

# obtener todas las tablas cargadas
tables = metadata.tables

# endpoint para realizar consultas a la base de datos
@app.route('/query', methods=['POST'])
def query():
    try:
        # obtener el archivo de configuración desde el formdata
        config_file = request.files['config'].read()
        
        # convertir el archivo de configuración en un diccionario
        config = json.loads(config_file)

        # crear una lista de tablas a seleccionar
        table_list = []
        for table_config in config['tables']:
            table = tables[table_config['name']]
            if table_config.get('columns'):
                columns = [table.c[column] for column in table_config['columns']]
                table_list.append(select(columns).select_from(table))
            else:
                table_list.append(table)

        # crear las cláusulas join
        for join in config['join']:
            primary_table = tables[join['table']]
            foreign_table = tables[join['foreign_table']]
            join_condition = primary_table.c[join['primary_key']] == foreign_table.c[join['foreign_key']]
            table_list.append(primary_table.join(foreign_table, join_condition))

        # construir la consulta final
        query = table_list[0]
        for table in table_list[1:]:
            query = query.join(table)

        # ejecutar la consulta
        conn = engine.connect()
        result = conn.execute(query)

        # construir la respuesta
        response = []
        for row in result:
            response.append(dict(row))
        
        # cerrar la conexión a la base de datos
        conn.close()

        # devolver la respuesta como JSON
        return jsonify(response)
    except Exception as e:
        return { "mensaje": "Hubo un error no esperado. "+str(e), "error": True}

