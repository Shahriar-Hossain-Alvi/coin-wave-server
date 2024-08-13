const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;


//middleware
app.use(cors({
    origin: ['http://localhost:5173',
        'https://coin-wave-financial-service.netlify.app', 'https://coin-wave-financial-service.netlify.app/login']
}))
app.use(express.json());



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
        const sendMoneyCollection = client.db("coinWave").collection("sendMoney");
        const serviceChargeCollection = client.db("coinWave").collection("serviceCharge");
        const cashInRequestCollection = client.db("coinWave").collection("cashIn");
        const cashOutRequestCollection = client.db("coinWave").collection("cashOut");


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

        //verify Admin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            next();
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

            if (user.status === 'pending') {
                const accountStatus = user.status;
                const message = "Account is not activated";
                return res.send({ accountStatus, message });
            }

            if (user.status === 'blocked') {
                const accountStatus = user.status;
                const message = "Your account has been blocked";
                return res.send({ accountStatus, message });
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
        app.get('/allUsers', verifyToken, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();

            res.send(result);
        })

        //update user status by admin
        app.patch('/user', verifyToken, verifyAdmin, async (req, res) => {
            const { id, status } = req.body;

            const filter = { _id: new ObjectId(id) };

            const updateDocument = {
                $set: {
                    status: status,
                },
            };

            const result = await usersCollection.updateOne(filter, updateDocument);

            res.send(result)
        })


        //update user info after first login
        app.patch('/usersFirstLogin', verifyToken, async (req, res) => {
            const { id } = req.body;

            const filter = { _id: new ObjectId(id) };
            const user = await usersCollection.findOne(filter);
            const newBalance = user.balance + 40;

            const updateDocument = {
                $set: {
                    firstTimeLogin: 'no',
                    balance: newBalance,
                },
            };

            const result = await usersCollection.updateOne(filter, updateDocument);

            res.send(result)
        })


        //update user info after first login
        app.patch('/usersFirstLogin', verifyToken, async (req, res) => {
            const { id } = req.body;

            const filter = { _id: new ObjectId(id) };
            const user = await usersCollection.findOne(filter);

            const newBalance = user.balance + 40;

            const updateDocument = {
                $set: {
                    firstTimeLogin: 'no',
                    balance: newBalance,
                },
            };

            const result = await usersCollection.updateOne(filter, updateDocument);

            res.send(result)
        })


        //update agent info after first login
        app.patch('/agentsFirstLogin', verifyToken, async (req, res) => {
            const { id } = req.body;

            const filter = { _id: new ObjectId(id) };
            const user = await usersCollection.findOne(filter);

            const newBalance = user.balance + 10000;

            const updateDocument = {
                $set: {
                    firstTimeLogin: 'no',
                    balance: newBalance,
                },
            };

            const result = await usersCollection.updateOne(filter, updateDocument);

            res.send(result);
        })


        //search for receiver before sending money
        app.get('/receiverInfo', verifyToken, async (req, res) => {

            const receiverNumber = req.query.receiverNumber;
            const senderNumber = req.query.senderNumber;

            const query = {
                mobileNumber: receiverNumber
            }

            const receiver = await usersCollection.findOne(query);

            if (!receiver || receiver.role !== 'user') {
                return res.send({ message: "not found" })
            }

            else if (receiver.mobileNumber === senderNumber) {
                return res.send({ message: "same number" });
            }

            res.send(receiver);
        })

        //add the send money info to server database
        app.post('/sendMoney', verifyToken, async (req, res) => {

            // get the data from the client side
            const { senderName, senderEmail, senderMobileNumber, receiverName, receiverEmail, receiverMobileNumber, sentAmount, pin } = req.body;

            // get sender info from users collection
            const getSenderInfo = await usersCollection.findOne({ email: senderEmail });


            // Compare the senders PIN with the stored hashed PIN
            const sendersStoredPin = getSenderInfo.pin;
            const isMatch = bcrypt.compareSync(pin.toString(), sendersStoredPin);

            if (!isMatch) {
                return res.send({ message: "Incorrect PIN number" });
            }


            // Deduct 5 TK as service charge if the sent amount is greater than 100 TK also deduct sent amount from users balance
            let serviceCharge = 0;
            if (sentAmount > 100) {
                serviceCharge = 5;
            }
            const newBalance = getSenderInfo.balance - sentAmount - serviceCharge;


            // Update sender's balance
            await usersCollection.updateOne(
                { email: senderEmail },
                { $set: { balance: newBalance } }
            );


            //generate transaction ID and insert the transaction data inn the DB
            const transactionId = `Tnx${Date.now()}`;
            const transactionTime = new Date();

            sendMoneyInfo = { senderName, senderEmail, senderMobileNumber, receiverName, receiverEmail, receiverMobileNumber, sentAmount, transactionId, transactionTime }

            const result = await sendMoneyCollection.insertOne(sendMoneyInfo);

            // insert service charge into the serviceChargeCollection
            if (serviceCharge > 0) {
                await serviceChargeCollection.insertOne({
                    transactionId,
                    senderEmail,
                    senderMobileNumber,
                    senderName,
                    sentAmount,
                    serviceCharge,
                    date: new Date()
                });
            }

            res.send(result);
        });

        //update the money in the receivers account
        app.patch('/updateReceiversBalance', verifyToken, async (req, res) => {
            const { sentAmount, receiverEmail } = req.body;

            const query = {
                email: receiverEmail
            }

            //get receivers info
            const receiver = await usersCollection.findOne(query);

            //set new balance
            const currentBalance = receiver.balance;
            const updatedBalance = currentBalance + sentAmount;

            const updateDocument = {
                $set: {
                    balance: updatedBalance
                }
            }

            const result = await usersCollection.updateOne(query, updateDocument);

            res.send(result);
        })


        //get transaction record for current user
        app.get('/transactions/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            const query = {
                senderEmail: email
            }
            const result = await sendMoneyCollection.find(query).toArray();
            res.send(result);
        });


        //get all transaction record for admin
        app.get('/allTransactions', verifyToken, verifyAdmin, async (req, res) => {
            const result = await sendMoneyCollection.find().toArray();
            res.send(result);
        })


        //get agents list for cash in or out
        app.get('/agentsList', verifyToken, async (req, res) => {
            const query = {
                role: 'agent'
            }

            const result = await usersCollection.find(query).toArray();

            res.send(result);
        });


        // add cash in request to the server
        app.post('/cashInRequest', verifyToken, async (req, res) => {
            const cashInRequestInfo = req.body;

            const result = await cashInRequestCollection.insertOne(cashInRequestInfo);

            res.send({ message: 'successful' });
        })


        // get cash in requests from the DB for the agent
        app.get('/cashInRequests', verifyToken, async (req, res) => {
            const agentsEmailAddress = req.query;
            const email = agentsEmailAddress.agentEmail;

            const result = await cashInRequestCollection.find({ agentEmail: email }).toArray();

            res.send(result);
        })


        // add a status like accepted or rejected in cash in data
        app.patch('/cashInRequests', verifyToken, async (req, res) => {
            const { cashInId, cashInRequestStatus } = req.body;

            // update cash in collection
            const filter = { _id: new ObjectId(cashInId) };

            const updateDocument = {
                $set: {
                    cashInRequestStatus: cashInRequestStatus,
                },
            };

            const result = await cashInRequestCollection.updateOne(filter, updateDocument);

            res.send(result);
        })


        // update users and agents balance after successful cash in
        app.patch('/updateUserAndAgentBalanceAfterCashIn', verifyToken, async (req, res) => {
            const updatedInfo = req.body;

            const { userEmail, agentEmail, cashInAmount } = updatedInfo;

            // get the user and agent info to get their balance
            const user = await usersCollection.findOne
                ({ email: userEmail });

            const agent = await usersCollection.findOne({ email: agentEmail });

            //set new balance for user
            const usersCurrentBalance = user.balance;
            const usersUpdatedBalance = usersCurrentBalance + cashInAmount;

            const usersUpdateDocument = {
                $set: {
                    balance: usersUpdatedBalance,
                },
            }


            //set new balance for agent
            const agentsCurrentBalance = agent.balance;
            const agentsUpdatedBalance = agentsCurrentBalance - cashInAmount;

            const agentsUpdateDocument = {
                $set: {
                    balance: agentsUpdatedBalance,
                },
            }

            // Perform both updates in parallel
            const [userUpdateResult, agentUpdateResult] = await Promise.all([
                usersCollection.updateOne({ email: userEmail }, usersUpdateDocument),

                usersCollection.updateOne({ email: agentEmail }, agentsUpdateDocument)
            ]);

            // Check if both updates were successful
            if (userUpdateResult.modifiedCount > 0 && agentUpdateResult.modifiedCount > 0) {
                res.send({ success: true, message: "Balances updated successfully" });
            } else {
                res.status(400).send({ success: false, message: "Failed to update balances" });
            }

        })


        // add cash out request to the server
        app.post('/cashOutRequest', verifyToken, async (req, res) => {
            const cashOutRequestInfo = req.body;

            const result = await cashOutRequestCollection.insertOne(cashOutRequestInfo);

            res.send({ message: 'successful' });
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