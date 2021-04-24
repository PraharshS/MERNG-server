const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { UserInputError } = require("apollo-server");

const {
  validateRegisterInput,
  validateLoginInput,
} = require("../../util/validators");

// const { SECRET_KEY } = require("../../config");
const User = require("../../models/User");

function generateToken(res) {
  return jwt.sign(
    {
      id: res.id,
      email: res.email,
      username: res.username,
    },
    process.env.SECRET_KEY,
    { expiresIn: "1h" }
  );
}
module.exports = {
  Mutation: {
    async login(_, { username, password }) {
      //  Validate user data

      const object = validateLoginInput(username, password);

      const errors = object.errors;
      if (!object.valid) {
        throw new UserInputError("Errors", { errors });
      }
      const user = await User.findOne({ username });

      if (!user) {
        errors.general = "User not found";
        throw new UserInputError("User not found", { errors });
      }
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        errors.general = "Wrong credientials";
        throw new UserInputError("Wrong credientials", { errors });
      }
      const token = generateToken(user);
      return {
        ...user._doc,
        id: user.id,
        token,
      };
    },
    async register(
      _,
      { registerInput: { username, email, password, confirmPassword } }
    ) {
      //  Validate user data
      const object = validateRegisterInput(
        username,
        email,
        password,
        confirmPassword
      );

      const errors = object.errors;
      if (!object.valid) {
        throw new UserInputError("Errors", { errors });
      }
      //  Make sure user doesnt already exists

      const user = await User.findOne({ username });
      if (user) {
        throw new UserInputError("Username is taken", {
          errors: {
            username: "This username is taken",
          },
        });
      }
      password = await bcrypt.hash(password, 12);
      const newUser = new User({
        email,
        username,
        password,
        createdAt: new Date().toISOString(),
      });

      //   Register new user after all valiation checks
      const res = await newUser.save();

      const token = generateToken(res);

      return {
        ...res._doc,
        id: res.id,
        token,
      };
    },
  },
};
