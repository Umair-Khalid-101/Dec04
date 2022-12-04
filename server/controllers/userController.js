const dotenv = require("dotenv");
dotenv.config();
const _ = require("lodash");
const User = require("../models/userSignUpModel");
const bcrypt = require("bcryptjs");
const cloudinary = require("cloudinary").v2;
const axios = require("axios");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const register = async (req, res, next) => {
  let cloudinaryImage;
  let user = await User.findOne({ email: req.body.email });
  if (user) return res.status(400).send("User Already Registered.");

  const file = req.files.picture;
  await cloudinary.uploader.upload(file.tempFilePath, (err, result) => {
    cloudinaryImage = result.url;
  });
  user = new User({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    role: req.body.role,
    picture: cloudinaryImage,
  });
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);

  await user.save();

  const token = user.generateAuthToken();
  res
    .header("x-auth-token", token)
    .send(_.pick(user, ["_id", " name", "email", "role", "picture"]));
};

const facebookSignup = async (req, res) => {
  try {
    const { accessToken, id } = req.body;
    const { data } = await axios({
      url: `https://graph.facebook.com/${id}`,
      method: "get",
      params: {
        fields: [
          "id",
          "email",
          "first_name",
          "last_name",
          "picture.type(large)",
        ].join(","),
        access_token: accessToken,
      },
    });
    res.send(data); // { id, email, first_name, last_name }

    // const { password, ...rest } = user._doc;
    // res.status(200).send({ ...user._doc });
    res.status(403).send("User already exists");
    return;
  } catch (error) {
    console.error(error);
    res.status(500).send(error);
  }
};

const auth = async (req, res, next) => {
  const email = req.body.email;
  let user = await User.findOne({ email }).exec();
  if (!user) return res.status(400).send("Invalid Email");
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword) return res.status(400).send("Invalid Password");

  const token = user.generateAuthToken();
  res.send(token);
};

const currentUser = async (req, res, next) => {
  const user = await User.findById(req.user._id).select("-password");
  res.send(user);
};

const updateProfile = async (req, res, next) => {
  const id = req.params.id;
  // console.log("ID: ", id);
  // console.log("Req: ", req.body);
  const options = { new: true };
  try {
    const result = await User.findByIdAndUpdate(
      id,
      {
        $set: {
          name: req.body.name,
          email: req.body.email,
          picture: req.body.picture,
        },
      },
      options
    );
    res.status(200).json(result);
  } catch (error) {
    console.log(error.message);
  }
};

exports.register = register;
exports.auth = auth;
exports.currentUser = currentUser;
exports.updateProfile = updateProfile;
exports.facebookSignup = facebookSignup;
