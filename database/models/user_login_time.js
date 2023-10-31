module.exports = (sequelize,DataTypes) =>{
 const user_login_time = sequelize.define('user_login_time',{
    id:{
      type:DataTypes.INTEGER,
      autoIncrement:true,
      allowNull:false,
      primaryKey:true
    },
    user_id:{
      type:DataTypes.INTEGER,
      allowNull:true,
    },
    login_time:{
      type:DataTypes.INTEGER,
      allowNull:true
    }
 },{timeStamps:true})
 return user_login_time;
}
