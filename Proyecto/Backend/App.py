from flask import Flask, jsonify, request
from flask_cors import CORS
from flasgger import Swagger
import bcrypt
import pymysql


app= Flask(__name__)
CORS(app)
swagger = Swagger(app)

# Conexión a la base de datos
def conectar(vhost, vuser, vpass, vdb):
    conn= pymysql.connect(host=vhost, user=vuser, password=vpass, db=vdb, charset='utf8')
    return conn

# Ruta para consulta general
@app.route("/", methods=['GET'])
def consulta_general():
    """
    consulta general del baul de contraseñas
    ---
    responde:
      200:
        description: Lista de regristos
    """
    try:
        conn = conectar('localhost', 'root', '', 'gestor_contrasena')
        cur= conn.cursor()
        cur.execute("SELECT * FROM baul")
        datos= cur.fetchall()
        data= []
        for row in datos:
             dato= {'id_baul': row[0], 'plataforma': row[1], 'usuario': row[2], 'clave': row[3]}
             data.append(dato)
        cur.close()
        conn.close()
        return jsonify({'baul': data, 'mensaje': 'Baul de contraseña'})
    except Exception as ex:
        print(ex)
        return jsonify({'mensaje':str(ex)})
    
# Ruta para consulta individual
@app.route("/consulta_individual/<codigo>", methods=['GET'])
def consulta_individual(codigo):
    """
    consulta individual del baul de contraseñas
    ---
    parameters:
      - name: codigo
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Registro encontrado
    """
    try:
        conn = conectar('localhost', 'root', '' ,'gestor_contrasena')
        cur= conn.cursor()
        # Usar parámetros de consulta para mayor seguridad
        cur.execute("SELECT * FROM baul WHERE id_baul = %s", (codigo,))
        dato = cur.fetchone() # Asigna el resultado a 'dato'
        cur.close()
        conn.close()
        if dato: # Ahora se verifica 'dato' en lugar de 'datos'
            # Se usa 'dato' para construir el diccionario
            dato_formato = {'id_baul': dato[0], 'plataforma': dato[1], 'usuario': dato[2], 'clave': dato[3]}
            return jsonify({'baul': dato_formato, 'mensaje': 'Registro encontrado'})
        else:
            return jsonify({'mensaje': 'Registro no encontrado'})
    except Exception as ex:
        print(ex)
        return jsonify({'mensaje': 'Error al consultar el registro'})

#Ruta para registro
@app.route("/registro/", methods=['POST'])
def registro():
    """
    Registro nueva contraseñas
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            plataforma:
              type: string
            usuario:
              type: string
            contraseña:
              type: string
    responses:
      200:
        description: Registro exitoso
    """
    try:
        data = request.get_json()
        plataforma = data['plataforma']
        usuario = data['usuario']
        hashed = bcrypt.hashpw(data['clave'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = conectar('localhost', 'root', '', 'gestor_contrasena')
        cur = conn.cursor()
        cur.execute("INSERT INTO baul (plataforma, usuario, clave) VALUES (%s, %s, %s)", (plataforma, usuario, hashed))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'mensaje': 'Registro exitoso'})
    except Exception as ex:
        print(ex)
        return jsonify({'mensaje': 'Error al registrar el usuario'})
#Ruta para eliminar registro
@app.route("/eliminar/<codigo>", methods=['DELETE'])
def eliminar(codigo):
    """
    Eliminar registro por ID
    ---
    parameters:
      - name: codigo
        in: path
        required: true
        type: integer
    responses:
      200:
        description: Registro eliminado exitosamente
    """
    try:
        conn = conectar('localhost', 'root', '' , 'gestor_contrasena')
        cur = conn.cursor()
        cur.execute("DELETE FROM baul WHERE id_baul = %s", (codigo,))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'mensaje': 'Registro eliminado exitosamente'})
    except Exception as ex:
        print(ex)
        return jsonify({'mensaje': 'Error al eliminar el registro'})

# Ruta para actualizar registro
@app.route("/actualizar/<codigo>", methods=['PUT'])
def actualizar(codigo):
    """
    Actualizar registro por ID
    ---
    parameters:
      - name: codigo
        in: path
        required: true
        type: integer
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            plataforma:
              type: string
            usuario:
              type: string
            contraseña:
              type: string
    responses:
      200:
        description: Registro actualizado exitosamente
    """
    try:
        data = request.get_json()
        plataforma = data['plataforma']
        usuario = data['usuario']
        hashed = bcrypt.hashpw(data['clave'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = conectar('localhost', 'root', '', 'gestor_contrasena')
        cur = conn.cursor()
        cur.execute("UPDATE baul SET plataforma = %s, usuario = %s, clave = %s WHERE id_baul = %s", (plataforma, usuario, hashed, codigo))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'mensaje': 'Registro actualizado exitosamente'})
    except Exception as ex:
        print(ex)
        return jsonify({'mensaje': 'Error al actualizar el registro'})
    
if __name__== '__main__':
    app.run(debug=True)