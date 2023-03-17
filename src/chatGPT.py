import os
import pandas as pd
from flask import Flask, request, jsonify
from sqlalchemy import create_engine

app = Flask(__name__)

@app.route('/loaddata', methods=['POST'])
def load_data():
    engine = create_engine('postgresql://username:password@localhost:5432/db_name')
    files = request.files.getlist('files')

    for file in files:
        file_type = os.path.splitext(file.filename)[1]

        if file_type == '.xlsx':
            df = pd.read_excel(file)
        elif file_type == '.csv':
            df = pd.read_csv(file)
        elif file_type == '.html':
            df = pd.read_html(file)[0]

        for col in df.columns:
            try:
                df[col] = pd.to_numeric(df[col], errors='raise')
            except ValueError:
                pass

        df.to_sql(file.filename, con=engine, index=False, if_exists='replace')
    
    return jsonify({'message': 'Data loaded successfully'})


@app.route('/query', methods=['POST'])
def query_data():
    engine = create_engine('postgresql://username:password@localhost:5432/db_name')
    config = request.json

    results = []

    for table in config['tables']:
        table_name = table['name']
        query_columns = table.get('columns')

        if query_columns:
            query = f"SELECT {', '.join(query_columns)} FROM {table_name}"
        else:
            query = f"SELECT * FROM {table_name}"

        df = pd.read_sql_query(query, con=engine)
        results.append({table_name: df.to_dict('records')})

    return jsonify(results)
