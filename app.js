require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config Json response
app.use(express.json());

// Models
const User = require('./models/User');

// Rota Publica
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API!" });
});

// Rota Privada
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // verifica user
    const user = await User.findById(id, '-password');

    if(!user){
        return res.status(404).json({ msg: "Usuário não encontrado" });
    }

    try {
        res.status(200).json({user});
    } catch (error) {
        res.status(500).json({ msg: "Aconteceu um erro em nosso servidor tente novamente mais tarde!" });
    }
});

function checkToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token){
        return res.status(401).json({ msg: "Acesso negado." });
    }

    try {
        
        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();

    } catch (error) {
        res.status(400).json({ msg: "Token invalido" });
    }
}

// Criar Usuario
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body;

    // validações
    if (!name) {
        return res.status(422).json({ msg: "Nome é um campo obrigatório" });
    }

    if (!email) {
        return res.status(422).json({ msg: "Email é um campo obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "Senha é um campo obrigatório" });
    }

    if (!confirmpassword) {
        return res.status(422).json({ msg: "Confirmação de senha é um campo obrigatório" });
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas não conferem!" });
    }

    // verifica se existe o user
    const userExist = await User.findOne({ email: email });

    if (userExist) {
        return res.status(422).json({ msg: "Email em uso, por favor utilize outro email" });
    }

    // cria senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // criação de usuario:
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {

        await user.save();

        res.status(201).json({ msg: "Usuário criado com sucesso!" });

    } catch (error) {
        res.status(500).json({ msg: "Aconteceu um erro em nosso servidor tente novamente mais tarde!" });
    }
});

// Rota de Login
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({ msg: "Email é um campo obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "Senha é um campo obrigatório" });
    }

    // verifica se existe o user
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado." });
    }

    // check senha match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha invalida." });
    }

    try {

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({msg: "Autenticação realizada com sucesso", token});

    } catch (error) {
        res.status(500).json({ msg: "Aconteceu um erro em nosso servidor tente novamente mais tarde!" });
    }
});

// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.9yrw5.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() => {
    app.listen(3000);
    console.log('Conectado');
}).catch((err) => console.log(err));