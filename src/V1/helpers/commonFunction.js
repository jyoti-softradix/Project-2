import randomstring from "randomstring";
import AWS from "aws-sdk";
import fs from "fs";

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});
const s3 = new AWS.S3();
const AWS_SES = new AWS.SES();

/****  get user roles  ****/
export const getAccessRoles = async (db) => {
  const userAccess = {};
  const userRoles = await db.models.Roles.findAll({ raw: true });

  for (const ele of userRoles) {
    if (ele.name == "Admin") {
      userAccess.Admin = ele.id;
    }
    if (ele.name == "User") {
      userAccess.SalesRepresentative = ele.id;
    }
    if (ele.name == "Club Owner") {
      userAccess.ClubOwner = ele.id;
    }
  }

  return userAccess;
};
  /** generate otp method */
  export const generateOTP = async () => {
    return Math.floor(1000 + Math.random() * 9000);
  }

/** **  Function for upload file to S3 Bucket  *** */
export const uploadFileToAWS = async (params) =>
  new Promise((resolve, reject) => {
    s3.upload(params, (err, response) => {
      if (err) {
        console.log(err);
        reject(err);
      } else {
        resolve(response);
      }
    });
  });

/* upload file common function*/
export const uploadFileForAll = async (detail) => {
  const { files, id, folder } = detail;
  try {
    const uploadedFiles = [];
    for (const ele of files) {
      const data = fs.readFileSync(ele.path);
      fs.unlinkSync(ele.path);
      const params = {
        Bucket: process.env.AWS_BUCKET,
        Key: `${folder}/${id}/${Date.now()}-renAthletics.${ele.originalname
          .split(".")
          .pop()}`,
        Body: data,
        contentType: ele.mimetype,
        ACL: "public-read",
      };
      // console.log("params :", params)
      const result = await uploadFileToAWS(params);
      ele.location = result.Location;
      ele.key = result.Key;
    }
    if (files) {
      if (files.length > 0) {
        files.forEach((file) => {
          const upload = {
            path: file.location,
            type: file.mimetype,
            name: file.originalname,
            file_key: file.key,
          };
          uploadedFiles.push(upload);
        });
      }
    }
    return uploadedFiles;
  } catch (error) {
    console.log(error, "======");
  }
};

export const s3RemoveSingleFile = async (key) =>
  new Promise((resolve, reject) => {
    const deleteParam = {
      Bucket: process.env.AWS_BUCKET,
      Key: key,
    };
    s3.deleteObject(deleteParam, (error, response) => {
      if (error) {
        return reject(error);
      }
      return resolve(response);
    });
  });

export const s3RemoveMultipleFile = async (keys) =>
  new Promise((resolve, reject) => {
    const deleteParams = {
      Bucket: process.env.AWS_BUCKET,
      Delete: {
        Objects: keys,
      },
    };
    s3.deleteObjects(deleteParams, (error, response) => {
      if (error) {
        return reject(error);
      }
      return resolve(response);
    });
  });

/* upload pdf to S3 bucket function*/
export const uploadPdfToS3 = async (invoicePdf, storeId, orderId) => {
  try {
    if (invoicePdf) {
      const pdfBuffer = Buffer.from(invoicePdf);
      const params = {
        Bucket: process.env.AWS_BUCKET,
        Key: `${storeId}/receipt/${orderId}/${Date.now()}-renAthletics.${"receipt-order.pdf"
          .split(".")
          .pop()}`,
        Body: pdfBuffer,
        ACL: "public-read",
      };
      const result = await uploadFileToAWS(params);
      return { pdf: result.Location };
    }
  } catch (error) {
    console.log(error, "======");
  }
};
