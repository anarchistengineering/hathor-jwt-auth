const JWT = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {
  isHtmlPage
} = require('hathor-utils');

const generateRandomKey = ()=>{
  return require('crypto').randomBytes(256).toString('base64');
};

const findUser = (username, password, config, callback)=>{
  const userHandler = config.get('userHandler', false);
  if(userHandler){
    return userHandler(username, password, callback);
  }
  const users = config.get('users', false);
  if(Array.isArray(users)){
    const uname = username.toLowerCase();
    const matches = users.filter((user)=>user.username.toLowerCase()===uname);
    const user = matches.shift();
    if(!user){
      return callback(null, false);
    }
    return bcrypt.compare(password, user.password, (err, isValid)=>{
      if(err){
        return callback(err);
      }
      if((!isValid) && (user.password === password)){
        return callback(null, true, user);
      }
      return callback(err, isValid, user);
    });
  }
  return callback(new Error('Attempt to use JWT auth with no users or no userHandler defined!'));
};

const defaultValidateFunc = (decoded, request, callback)=>{
  if(decoded.expires){
    const now = (new Date()).getTime();
    if(expires <= now){
      return callback(null, false);
    }
  }
  return callback(null, decoded.valid);
};

module.exports = function(server, options){
  const config = options.get('auth');
  const logger = server.logger;
  const {
    whitelist = [],
    blacklist = [],
    loginLandingPage,
    logoutPath,
    logoutRedirectTo,
    key = generateRandomKey()
  } = config.toJS();
  const ttl = config.get('TTL', config.get('ttl'));
  const cookie_options = {
    ttl,
    encoding: 'none',
    isSecure: true,
    isHttpOnly: true,
    clearInvalid: true,
    strictHeader: true
  };
  const whitelistPages = (whitelist && whitelist.length)?
          whitelist.map((page)=>{
            const pageIsHTML = isHtmlPage(page);
            return pageIsHTML?{
              method: 'GET',
              path: `/${page}`,
              auth: false,
              handler: {
                file: {
                  path: page
                }
              }
            }:{
              method: 'GET',
              path: `/${page}/{param*}`,
              auth: false,
              handler: {
                directory: {
                  path: `${page}/.`,
                  redirectToSlash: true,
                  index: true
                }
              }
            };
          }).filter((p)=>!!p):
          [];
  const blacklistPages = (blacklist && blacklist.length)?
          blacklist.map((page)=>{
            const pageIsHTML = isHtmlPage(page);
            return pageIsHTML?{
              method: 'GET',
              path: `/${page}`,
              auth: true,
              handler: {
                file: {
                  path: page
                }
              }
            }:{
              method: 'GET',
              path: `/${page}/{param*}`,
              auth: true,
              handler: {
                directory: {
                  path: `${page}/.`,
                  redirectToSlash: true,
                  index: true
                }
              }
            };
          }).filter((p)=>!!p):
          [];

  return {
    type: 'jwt',

    routes(server, options){
      const routes = [
        {
          method: 'POST',
          path: config.get('loginPath', '/login'),
          handler(req, reply){
            const {
              username,
              password
            } = req.payload;
            if(username && password){
              logger.info(`User auth attempt:`, username);
              return findUser(username, password, config, (err, isValid, account)=>{
                if(err){
                  return reply(err.toString()).code(401);
                }
                if(!isValid){
                  return reply('"Invalid username or password"').code(401);
                }
                const session = {
                  valid: true
                };
                const token = JWT.sign(session, key);
                return reply(`"${token}"`).header('Authorization', token).state('token', token, cookie_options);
              });
            }
            return reply('"Missing username or password"').code(401);
          }
        },
        {
          method: ['GET', 'POST'],
          path: logoutPath || '/logout',
          handler(req, reply){
            return reply.redirect(logoutRedirectTo || '/').header('Authorization', '').state('token', '', cookie_options);
          }
        }
      ];
      return routes.concat(whitelistPages).concat(blacklistPages).filter((p)=>!!p);
    },

    postRegister(server, options, next){
      const validateFunc = config.get('validateFunc', defaultValidateFunc);

      server.auth.strategy('jwt', 'jwt', Object.assign(
        {
          key,
          validateFunc,
          verifyOptions: {
            algorithms: config.get('algorithms', [ 'HS256' ]) // pick a strong algorithm
          }
        }, config.get('plugin', {}).toJS())
      );

      return next();
    },

    plugin: require('hapi-auth-jwt2')
  };
};
