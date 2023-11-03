import json
import os
import pandas as pd
from flask import Flask, jsonify, request
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
import sqlite3
# Obtener el string de conexión de la base de datos desde una variable de ambiente
db_uri = os.environ.get('DB_URI')
engine = create_engine(db_uri)

app = Flask(__name__)

@app.route('/loaddata', methods=['POST'])
def load_data_and_query():
    try:
        # Obtener los archivos de Excel y el archivo de configuración del formulario
        excel_files = request.files.getlist('excel_files')
        config_file = request.files.get('config_file')
        # Leer el archivo de configuración
        config = json.load(config_file)
        metadata = MetaData()
    
        for file in excel_files:
            try:
                df = pd.read_excel(file)
            except Exception as e:
                try:
                    df = pd.read_html(file)
                    df = pd.concat(df)
                except Exception as e:
                    continue
            df = df.applymap(lambda x: str(x).strip() if isinstance(x, str) else x) # Eliminar espacios en blanco alrededor de los strings
   
            table_name = file.filename.split(".")[0]
            columns = []
            for col in df.columns:
                col_type = str(df[col].dtype)
                try:
                    if col_type.startswith('float'):
                        df[col] = df[col].fillna(0).astype('int64').astype(str)
                    elif col_type.startswith('int'):
                        df[col] = df[col].astype(str)
                    columns.append(Column(col, String))
                except ValueError:
                    df[col] = df[col].astype(str)                   
                    columns.append(Column(col, String))
                    
            table = Table(table_name, metadata, *columns)


            metadata.create_all(engine)
            df.to_sql(table_name, engine, if_exists='replace', index=False)
        
        metadata = MetaData()
        return { "mensaje": "Carga exitosa"+str(e), "error": False}
        
    except Exception as e:
        return { "mensaje": "Hubo un error no esperado. "+str(e), "error": True}
@app.route('/loaddata', methods=['POST'])
def load_data_and_query2():
    try:
        # Obtener los archivos de Excel y el archivo de configuración del formulario
        excel_files = request.files.getlist('excel_files')
        config_file = request.files.get('config_file')
        # Leer el archivo de configuración
        config = json.load(config_file)
        metadata = MetaData()
    
        for file in excel_files:
            try:
                df = pd.read_excel(file)
            except Exception as e:
                try:
                    df = pd.read_html(file)
                    df = pd.concat(df)
                except Exception as e:
                    continue
            df = df.applymap(lambda x: str(x).strip() if isinstance(x, str) else x) # Eliminar espacios en blanco alrededor de los strings
   
            table_name = file.filename.split(".")[0]
            columns = []
            for col in df.columns:
                col_type = str(df[col].dtype)
                try:
                    if col_type.startswith('float'):
                        df[col] = df[col].fillna(0).astype('int64').astype(str)
                    elif col_type.startswith('int'):
                        df[col] = df[col].astype(str)
                    columns.append(Column(col, String))
                except ValueError:
                    df[col] = df[col].astype(str)                   
                    columns.append(Column(col, String))
                    
            table = Table(table_name, metadata, *columns)


            metadata.create_all(engine)
            df.to_sql(table_name, engine, if_exists='replace', index=False)
        
        metadata = MetaData()
        return { "mensaje": "Carga exitosa"+str(e), "error": False}
        
    except Exception as e:
        return { "mensaje": "Hubo un error no esperado. "+str(e), "error": True}
    
@app.route('/consulta', methods=['POST'])
def consulta():
    try:
        config_file = request.files.get('configuracion')
            # Leer el archivo de configuración
        configuracion = json.load(config_file)
        #configuracion = json.loads(request.form['configuracion'])

        # Generamos la lista de tablas a consultar y los campos a seleccionar
        tablas = ""
        campos = "*"
        for tabla in configuracion["tables"]:
            tablas += tabla["name"] + ","
            if "columns" in tabla and tabla["columns"]:
                campos += ",".join(f'"{col}"' for col in tabla["columns"]) + ","


        tablas = tablas[:-1]

        # Generamos la cláusula JOIN
        join = ""
        if "join" in configuracion:
            join = f'INNER JOIN "{configuracion["join"][0]["table"]}" ON "{configuracion["join"][0]["table"]}"."{configuracion["join"][0]["foreign_key"]}"="{configuracion["join"][0]["primary_key"]}"'

        # Generamos la cláusula WHERE si se especificó en el archivo de configuración
        where = ""
        if "where" in configuracion:
            where = " WHERE " + configuracion["where"]

        # Generamos la consulta SQL
        sql = f"SELECT {campos} FROM {tablas} {join} {where}"


        # Realizamos la consulta a la base de datos
        conexion = sqlite3.connect('database.db')
        cursor = conexion.cursor()
        cursor.execute(sql)
        resultados = cursor.fetchall()
        conexion.close()


        return jsonify(resultados)
    except Exception as e:
        return { "mensaje": "Hubo un error no esperado. "+str(e), "error": True}

""" import json
import os
import pandas as pd
from flask import Flask, jsonify, request
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Float

# Obtener el string de conexión de la base de datos desde una variable de ambiente
db_uri = os.environ.get('DB_URI')
engine = create_engine(db_uri)

app = Flask(__name__)

@app.route('/loaddata', methods=['POST'])
def load_data_and_query():
    try:
        # Obtener los archivos de Excel y el archivo de configuración del formulario
        excel_files = request.files.getlist('excel_files')
        config_file = request.files.get('config_file')
        # Leer el archivo de configuración
        #config = pd.read_json(config_file)
        config = json.load(config_file)
        metadata = MetaData()
    
        for file in excel_files:
            try:
                df = pd.read_excel(file)
            except Exception as e:
                try:
                    df = pd.read_html(file)
                    df = pd.concat(df)
                except Exception as e:
                    continue
            df = df.applymap(lambda x: str(x).strip() if isinstance(x, str) else x) # Eliminar espacios en blanco alrededor de los strings
   
            table_name = file.filename.split(".")[0]
            columns = []
            for col in df.columns:
                col_type = str(df[col].dtype)
                try:
                    if col_type.startswith('float'):
                        df[col] = df[col].fillna(0).astype('int64').astype(str)
                    elif col_type.startswith('int'):
                        df[col] = df[col].astype(str)
                    columns.append(Column(col, String))
                except ValueError:
                    df[col] = df[col].astype(str)                   
                    columns.append(Column(col, String))
                    
            table = Table(table_name, metadata, *columns)


            metadata.create_all(engine)
            df.to_sql(table_name, engine, if_exists='replace', index=False)
        
        metadata = MetaData()

        tables = []
        for table_config in config['tables']:
            table_name = table_config['name']
            if 'columns' in table_config and len(table_config['columns']) > 0:
                columns = [Column(col, String) for col in table_config['columns'] if col in df.columns]
            else:
                columns = [Column(col, String) for col in df.columns]
            table = Table(table_name, metadata, *columns)
            tables.append(table)

        tables = []
        select_columns = []
        for table_config in config['tables']:
            table_name = table_config['name']
            columns = table_config.get('columns', [])
            tables.append(table_name)
            select_columns.extend([f"{table_name}.{col}" for col in columns])

        # Generar la consulta SQL
        join_conditions = []
        for join in config['join']:
            primary_key = join['primary_key']
            foreign_key = join['foreign_key']
            table_name = join['table']
            join_conditions.append(f"{tables[0]}.{primary_key} = {table_name}.{foreign_key}")
            tables.append(table_name)

        table_list = ", ".join([f"{table}" for table in tables])
        column_list = ", ".join(select_columns)
        join_list = " JOIN ".join([f"{table}" for table in tables[1:]])
        on_list = " ON ".join(join_conditions)

        query = f"SELECT {column_list} FROM {table_list} JOIN {join_list} ON {on_list}"
        results = pd.read_sql_query(query, engine)

        result_dicts = results.to_dict(orient='records')
        return jsonify(result_dicts)
    except Exception as e:
        return {"mensaje": "Hubo un error no esperado. "+str(e), "error": True}, 500
 """

 