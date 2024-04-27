from flask import Flask,request, jsonify
from models.User import Users
from database import db
from flask_login import LoginManager,login_user,current_user,logout_user,login_required

app = Flask(__name__)

#configs iniciais para o db
app.config['SECRET_KEY'] = "1234"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask_db'

login_manager = LoginManager()
## inicia db
db.init_app(app)
## inicia o metodo de login
login_manager.init_app(app)
login_manager.login_view = 'login' # rota para o login 



#busca o usuario para a autenticação
@login_manager.user_loader
def user_loader(user_id):
    return Users.query.get(user_id)

@app.route('/logout',methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message":"Logout realizado com sucesso"})

@app.route('/login', methods=['POST'])
def login():
    ##pega os dados da requisição
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        user = Users.query.filter_by(username = username).first()
        if user and user.password == password:
            # passa o usuario para o login
            login_user(user)
            # verificar se p usuario esta logado
            print(current_user.is_authenticated)
            return jsonify({"message":"Autenticação realizada com sucesso"})
        
    return jsonify({"message":"Credenciais invalidas"}), 400

@app.route('/create', methods=['POST'])
def create():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username and password:
        userAlreadyExists = Users.query.filter_by(username=username).first()
        if(userAlreadyExists): 
            return jsonify({"message":"Este username ja pertence a um usuario cadastrado"})
        user = Users(username=username, password=password,role='user')
        
        db.session.add(user)
        db.session.commit()
        return jsonify({"message":"Usuario criado com sucesso"})
    return jsonify({"message":"Insira corretamente os campos para cadastrar um usuário"})

@app.route('/profile/<int:id>', methods=['GET'])
@login_required
def read_profile(id):
    user = Users.query.filter_by(id=id).first()
    if user:
        return jsonify(user.username)
    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route("/update-password/<int:id>", methods=['PUT'])
@login_required
def update_password(id):
    if current_user.id!=id and current_user.role == 'user':
        return jsonify({'message':'Operação não permitida'}), 403
    data = request.json
    password= data.get('password')
    user = Users.query.filter_by(id=id).first()
    if(user):
        if(password):
            user.password = password
            db.session.commit()
            return jsonify({"message":f"A senha do usuario {user.username} foi atualizada com sucesso"})
        return jsonify({"message":"É necessario informar uma senha nova para continuar"}), 400
    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route('/delete-user/<int:id>',methods=['DELETE'])
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        return jsonify({'message':'Não permitido'}), 403
    if(current_user.id == id) :
        return jsonify({"message":"Não permitido"}), 403
    user = Users.query.filter_by(id=id).first()
    if(user):
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message":"Usuário deletado com sucesso"})        
    return jsonify({"message":"Usuário não encontrado"}), 404

if __name__ == '__main__':
    app.run(debug=True)