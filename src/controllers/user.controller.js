import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"

const generateAccessAndRefreshToken = async(userId)=>{
   try {
      const user = await User.findById(userId)
      const accessToken = user.generateAccessToken()
      const refreshToken = user.generateRefreshToken()

      user.refreshToken = refreshToken
      await user.save({validateBeforeSave : false})

      return {accessToken,refreshToken}

   } catch (error) {
      throw new ApiError(500, "Something Went Wronge While generating access and refreseh token!")
   }
}

const registerUser = asyncHandler(async (req,res)=>{
   // get user detail from frontend
   // validation not -- empty
   // check if user already exists : username,email
   // check for images, check for avatar
   // upload them to cloudinary , avatar
   // create user object - create entry in DB
   // remove password and refresh token  fields from response
   // check for user creation
   // return res

   const {fullName,email, username,password} = req.body
   // console.log("email :",email)
    
// ---------------------------------------------------------


   if([fullName,email,username,password].some((field)=> field?.trim() === "")){
      throw new ApiError(400, "All fields are required!")
   }

// ---------------------------------------------------------

   const existedUser = await User.findOne({
    $or: [{ username },{ email }]
   })

   if(existedUser){
    throw new ApiError(409, "User with this name & email already exists!")
   }

   console.log(req.files)
// ---------------------------------------------------------

   const avatarLocalPath = req.files?.avatar[0]?.path;
   // const coverImageLocalPath = req.files?.coverImage[0]?.path;

   let coverImageLocalPath;
   if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
      coverImageLocalPath = req.files.coverImage[0].path
   }

   if(!avatarLocalPath){
      throw new ApiError(400, "Avatar files is required!")
   }

// ---------------------------------------------------------
  
   const avatar = await uploadOnCloudinary(avatarLocalPath)
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   // console.log("req.body:", req.body);
   // console.log("coverImage:", req.files?.coverImage);

   if(!avatar){
      throw new ApiError(400, "Avatar files is required!")
   }

// ---------------------------------------------------------

   const user = await User.create({
    fullName,
    avatar:avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
   })

// ---------------------------------------------------------
   
   const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
   )

   if(!createdUser){
    throw new ApiError(500, "Something went wronge!")
   }

// ---------------------------------------------------------
   
   return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered Successfully!")
   )

})

const loginUser = asyncHandler(async (req,res)=>{
      // req body -> data
      // username or email
      // find the user
      // password check
      // access token & refresh token
      // send cookies

// ---------------------------------------------------------
   const {email,username,password} = req.body
   console.log(email)
// ---------------------------------------------------------
   if(!(username || email)){
      throw new ApiError(400, "username & email is required!")
   }
// ---------------------------------------------------------
   const user = await User.findOne({ 
      $or: [{username},{email}]
   })
// ---------------------------------------------------------
   if(!user){
      throw new ApiError(400, "User does not exist!")
   }
// ---------------------------------------------------------
   const isPasswordValid = await user.isPasswordCorrect(password)

   if(!isPasswordValid){
      throw new ApiError(401,"Password is Not Valid!")
   }
// ---------------------------------------------------------

   const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)
   
   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

// ---------------------------------------------------------
   
   const options = {
      httpOnly : true,
      secure : true
   }

   return res
   .status(200)
   .cookie("accessToken", accessToken, options)
   .cookie("refreshToken", refreshToken, options)
   .json(new ApiResponse(
      200,{
         user: loggedInUser, accessToken,
         refreshToken
      },
      "User LogedIn SUCCESSFULLY!"
   ))
})

const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
      req.user._id,
      {
         $set:{
            refreshToken:undefined 
         }
      },
       {
            new:true
      }
    )

    const options = {
      httpOnly:true, 
      secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User Logged Out!"))
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
   const incommingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

   if(!incommingRefreshToken){
      throw new ApiError(401, "unauthorized request!")
   }

 try {
     const decodedToken = jwt.verify(incommingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
  
     const user = await User.findById(decodedToken?._id)
  
     if(!user){
        throw new ApiError(401, "Invalid refresh Token")
     }
  
     if(incommingRefreshToken !== user?.refreshToken){
        throw new ApiError(401, "Refresh token is used OR Expired!")
     }
  
     const options = {
        httpOnly:true,
        secure:true
     }
     const {accessToken,newRefreshToken} = await generateAccessAndRefreshToken (user._id)
  
     return res
     .status(200)
     .cookie("Access token",accessToken,options)
     .cookie("Refresh Token",newRefreshToken,options)
     .json(
        new ApiError(200, {accessToken,refreshToken:newRefreshToken},"Access token refreshed!")
     )
 } catch (error) {
   throw new ApiError(401,error?.message || "Invalid refresh Token!")
 }
})

const changeCurrentPassword = asyncHandler(async(req,res)=>{
   const {oldPassword, newPassword}= req.body;

   const user = await User.findById(req.user?._id)
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

   if(!isPasswordCorrect){
      throw new ApiError(400, "Invalid old Password!")
   }

   user.password = newPassword 
   await user.save({validateBeforeSave:false})

   return res
   .status(200)
   .json(new ApiResponse(200,{}, "PasswordChanged Successfully!"))
})

const getCurrentUser = asyncHandler(async(req,res)=>{
   return res
   .status(200)
   .json(200, req.user, "Current user Fetched Successfully!")
})

const updateAccountDetails = asyncHandler(async(req,res)=>{
  const {fullName,email}= req.body;

  if(!(fullName || email)){
    throw new ApiError(400,"All fields are required!")
  }

  const user = User.findByIdAndUpdate(
   req.user?._id,
   {
   $set:{
      fullName,
      email
   }
  },
   {new:true}
  ).select("-password")

  return res
  .status(200)
  .json(new ApiResponse(200,user,"Account details updated Successfully!"))
})

const updateUserAvatar = asyncHandler(async(req,res)=>{
   const avatarLocalPath =  req.file?.path

   if(!avatarLocalPath){
      throw new ApiError(400, "Avatar fiel is Missing!")
   }

   const avatar =  await uploadOnCloudinary(avatarLocalPath)

   if(!avatar.url){
      throw new ApiError(400, "Error while Uploading on avatar!")
   }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set:{
            avatar:avatar.url
         }
      },
      {new:true}
   ).set("-password")

   return res
   .status(200)
   .json( new ApiResponse(200,user,"Avatar Image Updated Successfully!"))
})

const updateUserCoverImage = asyncHandler(async(req,res)=>{
   const coverImageLocalPath =  req.file?.path

   if(!coverImageLocalPath){
      throw new ApiError(400, "Cover file is Missing!")
   }

   const coverImage =  await uploadOnCloudinary(coverImageLocalPath)

   if(!coverImage.url){
      throw new ApiError(400, "Error while Uploading on avatar!")
   }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set:{
            coverImage:coverImage.url
         }
      },
      {new:true}
   ).set("-password")

   return res
   .status(200)
   .json( new ApiResponse(200,user,"Cover Image Updated Successfully!"))
})


export {registerUser ,loginUser,logoutUser , refreshAccessToken,changeCurrentPassword,getCurrentUser,updateAccountDetails,updateUserAvatar,updateUserCoverImage}