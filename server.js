import express from 'express';
import * as dotenv from 'dotenv';
import JWT from 'jsonwebtoken';

const app = express();
app.use(express.json());

dotenv.config();

// this would normally be a database
const posts = [
    {
        username: 'Zain',
        title: 'Post 1',
    },
    {
        username: 'Ali',
        title: 'Post 2',
    },
];

let refreshTokens = []; // normally this would be stored in a database or radix cache

app.get('/posts', authenticateToken, async (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name))
})

app.get('/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken === null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({name: user.name})
        res.json({accessToken: accessToken})
    })
})

app.get('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.get('/login', (req, res) => {
    const username = req.body.username;
    const user = {name: username};

    // const accessToken = JWT.sign(user, process.env.ACCESS_TOKEN_SECRET);
    const accessToken = generateAccessToken(user);
    const refreshToken = JWT.sign(user, process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);

    res.json({accessToken: accessToken, refreshToken: refreshToken});
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token === null) return res.sendStatus(401)

    JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

function generateAccessToken(user) {
    return JWT.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
}

app.get("/", (req, res) => {
    res.send(`Server STart on Port ${process.env.PORT}`);
});

const startServer = async () => {
    try {
        app.listen(process.env.PORT, () => console.log(`Server has started on port http://localhost:${process.env.PORT}`));
    } catch (error) {
        console.log(error, "---------Error start server-------");
    }
}

startServer();
