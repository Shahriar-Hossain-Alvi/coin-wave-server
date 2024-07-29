const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;


//middleware
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:5173']
}))



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.mfte2wh.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const usersCollection = client.db("coinWave").collection("users");


        //jwt related api
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '12h' });
            res.send({ token });
        })

        //verify token
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'Unauthorized access' });
            }
            const token = req.headers.authorization.split(' ')[1];

            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'Unauthorized access' });
                }
                req.decoded = decoded;
                next();
            })
        }


        //store users data after signup
        app.post('/signup', async (req, res) => {
            const { name, email, mobileNumber, pin, role, status, firstTimeLogin, balance, profileCreationTime } = req.body;

            const existingUser = await usersCollection.findOne({ email });

            if (existingUser) {
                return res.send({ message: "User already  exists" });
            }

            //Hash the pin
            const salt = bcrypt.genSaltSync(10);
            const hashedPin = bcrypt.hashSync(pin.toString(), salt);

            const newUser = { name, email, mobileNumber, pin: hashedPin, role, status, firstTimeLogin, balance, profileCreationTime }

            const result = await usersCollection.insertOne(newUser);

            res.send(result);
        })


        //login user with email and pin
        app.post('/login', async (req, res) => {
            const { email, pin, mobileNumber } = req.body;

            const user = email ? await usersCollection.findOne({ email }) : await usersCollection.findOne({ mobileNumber });


            if (!user) {
                return res.send({ message: "User not found. Sign up first if you don't have an account" });
            }

            // Compare the provided PIN with the stored hashed PIN
            const isMatch = bcrypt.compareSync(pin.toString(), user.pin);

            if (!isMatch) {
                return res.send({ message: "Invalid email or PIN" });
            }


            // If PIN matches, generate a token
            const token = jwt.sign({ email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '12h' });


            //send the token with the response body
            res.send({ token });
        })


        //get logged in user info
        app.get('/user', verifyToken, async (req, res) => {
            const user = await usersCollection.findOne({ email: req.decoded.email });

            if (!user) {
                return res.send({ message: 'User not found' });
            }
            res.send(user);
        })


        //get all user list for admin
        app.get('/allUsers', async (req, res) => {
            const result = await usersCollection.find().toArray();

            res.send(result);
        })


        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('Coin wave server is running');
})

app.listen(port, () => {
    console.log(`Coin Wave server is running on port ${port}`);
})