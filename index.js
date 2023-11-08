const jwt = require("jsonwebtoken");

exports.handler = async (event, context, callback) => {
  const token = getTokenFromHeader(event) || ''
  const methodArn = event.methodArn
  
  if(!token || !methodArn) return callback(null, generateAuthorizationResponse('user', 'Deny', methodArn))
  
  const jwtSecret = Buffer.from(process.env.jwt_secret, 'base64')
  
  try{
    const decodedToken = jwt.verify(token, jwtSecret)
    
    if(decodedToken && decodedToken.principalIdCustomer){
      return callback(null, generateAuthorizationResponse(decodedToken.principalIdCustomer, 'Allow', methodArn))
    }
    else {
      return callback(null, generateAuthorizationResponse('user', 'Deny', methodArn))
    }
  }
  catch(e){
    console.log('An error has occurred.', e)
    return callback(null, generateAuthorizationResponse('user', 'Deny', methodArn))
  }
}

function getTokenFromHeader(event){
  if(event.authorizationToken && event.authorizationToken.split(' ')[0] === 'Bearer'){
    return event.authorizationToken.split(' ')[1]
  }
  else{
    return event.authorizationToken
  }
}

function generateAuthorizationResponse(principalId, effect, methodArn){
  const policyDocument = generatePolicyDocument(effect, methodArn)
  
  return {
    principalId,
    policyDocument
  }
}

function generatePolicyDocument(effect, methodArn){
  if(!effect || !methodArn) return null
  
  return {
    Version: '2012-10-17',
    Statement: [{
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: methodArn
    }]
  }
}