// 모듈들 불러오기 (express모듈 사용, 미들웨어 사용)
var express = require('express'), http = require('http') , path = require('path');
var bodyParser = require('body-parser'), cookieParser = require('cookie-parser'), static = require('serve-static'), errorHandler = require('errorhandler');
var expressErrorHandler = require('express-error-handler');
var expressSession = require('express-session');
var mongoose = require('mongoose');// db 편의를 위한 mongoose 모듈
var crypto = require('crypto');

var app = express();// express 객체 생성

app.set('port', process.env.PORT || 3000);// port번호 : 3000
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use('/public', static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(expressSession({
   secret:'my key',
   resave:true,
   saveUninitialized:true
}));

var login_id;  //사용자 id를 받아오기 위한 변수
var database;
var UserSchema;
var MemoSchema;
var ReviewSchema;
var UserModel;
var MemoModel;
var ReviewModel;


function connectDB() { //DB연결 함수
   var databaseUrl = 'mongodb://localhost:27017/local';//db URL

    console.log('데이터베이스 연결을 시도합니다.');
    mongoose.Promise = global.Promise;
    mongoose.connect(databaseUrl);
   database = mongoose.connection;
   database.on('error', console.error.bind(console, 'mongoose connection error.'));
   database.on('open', function () {
    console.log('데이터베이스에 연결되었습니다. : ' + databaseUrl); //db 연결 성공!

    createSchema();//스키마(users3, memos, reviewpage) 생성 함수
   });

   database.on('disconnected', function() {
        console.log('연결이 끊어졌습니다. 5초 후 재연결합니다.');
        setInterval(connectDB, 5000);
    });
}

function createSchema() { //스키마 생성 함수
   UserSchema = mongoose.Schema({ //사용자 정보 스키마 생성
       id: {type: String, required: true, unique: true, 'default':''},
       hashed_password: {type: String, required: true, 'default':''},
       salt: {type:String, required:true},
       name: {type: String, index: 'hashed', 'default':''},
       age: {type: Number, 'default': -1},
       created_at: {type: Date, index: {unique: false}, 'default': Date.now},
       updated_at: {type: Date, index: {unique: false}, 'default': Date.now}
   });

  MemoSchema = mongoose.Schema({ //메모 정보 스키마 생성
       id: {type: String,  unique: true, 'default':''},
      content: {type: String, required: true, unique: true, 'default':''}
   });

  ReviewSchema = mongoose.Schema({ //게시판 정보 스키마 생성
     title: {type: String, required: true,  'default':''},
      id: {type: String,   'default':''},
      review: {type: String, required: true,  'default':''}
  });

   UserSchema
   .virtual('password')
     .set(function(password) {
       this._password = password;
       this.salt = this.makeSalt();
       this.hashed_password = this.encryptPassword(password);
       console.log('virtual password의 set 호출됨 : ' + this.hashed_password);
     })
     .get(function() {
           console.log('virtual password의 get 호출됨.');
           return this._password;
      });

   UserSchema.method('encryptPassword', function(plainText, inSalt) {   // 비밀번호 암호화하는 함수
      if (inSalt) {
         return crypto.createHmac('sha1', inSalt).update(plainText).digest('hex');
      } else {
         return crypto.createHmac('sha1', this.salt).update(plainText).digest('hex');
      }
   });

   UserSchema.method('makeSalt', function() {// salt 생성 함수
      return Math.round((new Date().valueOf() * Math.random())) + '';
   });

   UserSchema.method('authenticate', function(plainText, inSalt, hashed_password) { //입력 값(비밀번호)비교
      if (inSalt) {
         console.log('authenticate 호출됨 : %s -> %s : %s', plainText, this.encryptPassword(plainText, inSalt), hashed_password);
         return this.encryptPassword(plainText, inSalt) === hashed_password;
      } else {
         console.log('authenticate 호출됨 : %s -> %s : %s', plainText, this.encryptPassword(plainText), this.hashed_password);
         return this.encryptPassword(plainText) === this.hashed_password;
      }
   });

   var validatePresenceOf = function(value) {
      return value && value.length;
   };

   UserSchema.pre('save', function(next) { //비밀번호 유효성 판단 함수
      if (!this.isNew) return next();

      if (!validatePresenceOf(this.password)) {
         next(new Error('유효하지 않은 password 필드입니다.'));
      } else {
         next();
      }
   })

   MemoSchema.static('findAll', function(callback) {//memo스키마에  findAll 메소드 추가
       return this.find({}, callback);
    });
    MemoSchema.static('findById', function(callback) {//memo스키마에  findById 메소드 추가
        return this.find({}, callback);
     });
   UserSchema.static('findById', function(id, callback) {//user스키마에  findById 메소드 추가
      return this.find({id:id}, callback);
   });
   UserSchema.static('findAll', function(callback) {  //user스키마에  findAll 메소드 추가
      return this.find({}, callback);
   });
    ReviewSchema.static('findAll', function(callback) {//review스키마에  findAll 메소드 추가
      return this.find({}, callback);
  });

    ReviewSchema.static('findAll', function(callback) {//review스키마에  findAll 메소드 추가
        return this.find({}, callback);
   });

  MemoModel = mongoose.model("memos", MemoSchema);   // memos 정의
  UserModel = mongoose.model("users3", UserSchema);   // user 정의
  ReviewModel = mongoose.model("reviewpage", ReviewSchema);   // User 모델 정의
}

var router = express.Router();// 라우터 객체 참조

router.route('/process/login').post(function(req, res) {//해당 요청 패스에 대한 로그인 db정보와 비교하는 라우팅 함수
    var paramId = req.body.id || req.query.id; //post 요청 id 파라미터 변수로 지정
    var paramPassword = req.body.password || req.query.password;//post 요청 password 파라미터 변수로 지정

   login_id = paramId; //login_id 변수에 사용자 입력 id를 저장

   if (database) {
      authUser(database, paramId, paramPassword, function(err, docs) { //user를 인증하는 authuser 함수 호출
         if (err) {
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h2>사용자 로그인 중 에러 발생</h2>');
           res.write('<p>' + err.stack + '</p>');
            res.end();
            return;
        }
         if (docs) { //user정보가 존재하면 실행
            res.writeHead(302, { 'Location': '/public/bookhome.html' }); //로그인 성공시 bookhome.html 화면으로 이동
            res.end();
         }
         else {  //user정보가 존재하지 않으면 실행
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h1>로그인  실패</h1>');
            res.write('<div><p>아이디와 패스워드를 다시 확인하십시오.</p></div>');
            res.write("<br><br><a href='/public/login.html'>다시 로그인하기</a>");
            res.end();
         }
      });
   }
   else {
      res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
      res.write('<h2>데이터베이스 연결 실패</h2>');
      res.write('<div><p>데이터베이스에 연결하지 못했습니다.</p></div>');
      res.end();
   }
});

router.route('/process/review').post(function(req, res) {//게시판 추가 라우팅 함수
    var paramTitle = req.body.title|| req.query.title; //post 요청 title 파라미터 변수로 지정
    var paramReview = req.body.subject || req.query.subject; //post 요청 subject 파라미터 변수로 지정

    database.collection("reviewpage").insertOne({title: paramTitle, id: login_id, review: paramReview}, function(err, res){ //reviewpage에 데이터 추가, id는 로그인한 사용자 id를 변수로 받았음"
      if(err) throw err;
      console.log("1 document inserted");
    });
});

router.route('/process/adduser').post(function(req, res) { //사용자추가 라우팅 함수
    var paramId = req.body.id || req.query.id; //post 요청 id 파라미터 변수로 지정
    var paramPassword = req.body.password || req.query.password; //post 요청 password 파라미터 변수로 지정
    var paramName = req.body.name || req.query.name; //post 요청 name 파라미터 변수로 지정

   if (database) {
      addUser(database, paramId, paramPassword, paramName, function(err, addedUser) {//사용자를 추가(회원가입)하는 addUser 함수 호출

         if (err) {
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h2>사용자 추가 중 에러 발생</h2>');
            res.write('<p>' + err.stack + '</p>');
            res.end();
            return;
        }

         if (addedUser) {
            res.writeHead(302, {'Location': '/public/login.html' }); //사용자 추가(회원가입)에 성공하면 로그인 화면으로 이동
            res.end();
         }
         else {  // 결과 객체가 없으면 실패 응답 전송
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h2>사용자 추가  실패</h2>');
            res.end();
         }
      });
   }
    else {
      res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
      res.write('<h2>데이터베이스 연결 실패</h2>');
      res.end();
   }
});

router.route('/process/save').post(function(req, res) {//메모정보 초기저장 라우팅 함수
    var paramContent = req.body.content || req.query.content;//post 요청 content 파라미터 변수로 지정

   if (database) {
      addMemo(database, login_id, paramContent, function(err, addedMemo) {//메모를 저장하는 addMemo 함수 호출
         if (err) {
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h2>메모 추가 중 에러 발생</h2>');
            res.write('<p>' + err.stack + '</p>');
            res.end();
            return;
        }

         if (addedMemo) {
           res.writeHead(302, {  'Location': '/public/Mymemo.html' }); //메모장 저장에 성공하면 메모장 화면으로 이동
            res.end();
         }
         else {
            res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
            res.write('<h2>메모 추가  실패</h2>');
            res.end();
         }
      });
   }
    else {
      res.writeHead('200', {'Content-Type':'text/html;charset=utf8'});
      res.write('<h2>데이터베이스 연결 실패</h2>');
      res.end();
   }
});

router.route('/process/update').post(function(req, res) {//메모정보 수정 라우팅 함수
    var paramContent = req.body.content || req.query.content;//post 요청 content 파라미터 변수로 지정

    database.collection("memos").updateOne({id: login_id}, {$set: {content: paramContent}}, function(err, res) {//로그인한 id(login_id)에 해당하는 memos 정보에 메모 데이터 정보 수정
      if(err) throw err;
      console.log("1 document updated");
    });

    res.writeHead(302, {  'Location': '/public/Mymemo.html' });//메모장 저장에 성공하면 메모장 화면으로 이동
    res.end();
});

router.route('/process/lookup').post(function(req, res) {//메모정보 조회 라우팅 함수
  var a;
   console.log('/process/lookup 호출됨.');
   database.collection("memos").find({id: login_id},{ _id: 0, content: 1 }).toArray(function(err,result){
     if (err) throw err;
     res.send(result); //결과 전송
   });
});

router.route('/process/lookreview').post(function(req, res) {//게시판정보 조회 라우팅 함수
   database.collection("reviewpage").find({},{ _id: 0 }).toArray(function(err,result){
     if (err) throw err;
     res.send(result); //결과 전송
   });
});

app.use('/', router); // 라우터 객체 등록

var authUser = function(database, id, password, callback) {// 사용자 인증하는 함수 생성
   UserModel.findById(id, function(err, results) {// id를 이용하여 id가 일치하는 사용자 검색
      if (err) {
         callback(err, null);
         return;
      }
      console.log('아이디 [%s]로 사용자 검색결과', id);
      console.dir(results);
      if (results.length > 0) {
         console.log('아이디와 일치하는 사용자 찾음.');
         var user = new UserModel({id:id}); //usermoder 객체 생성
         var authenticated = user.authenticate(password, results[0]._doc.salt, results[0]._doc.hashed_password);//password 확인

         if (authenticated) {
            console.log('비밀번호 일치함');
            callback(null, results);
         }
         else {
            console.log('비밀번호 일치하지 않음');
            callback(null, null);
         }
      }
       else {
          console.log("아이디와 일치하는 사용자를 찾지 못함.");
          callback(null, null);
       }
   });
}


var addUser = function(database, id, password, name, callback) {//사용자 추가하는 함수 생성
   var user = new UserModel({"id":id, "password":password, "name":name});

   user.save(function(err, addedUser) {
      if (err) {
         callback(err, null);
         return;
      }
       console.log("사용자 데이터 추가함.");
       callback(null, addedUser);
   });
}

var addMemo = function(database, id, content, callback) {//메모를 초기 저장하는 함수 생성
   var memo = new MemoModel({"id":id,"content":content});

   memo.save(function(err, addedMemo) {
    if (err) {
         callback(err, null);
         return;
      }
     console.log("메모 데이터 추가함.");
     callback(null, addedMemo);
   });
}

var errorHandler = expressErrorHandler({//에러 핸들러 사용(404 에러)
 static: {
   '404': './public/404.html'
 }
});

app.use( expressErrorHandler.httpError(404) );
app.use( errorHandler );

process.on('SIGTERM', function () {
    console.log("프로세스가 종료됩니다.");
    app.close();
});

app.on('close', function () {
   console.log("Express 서버 객체가 종료됩니다.");
   if (database) {
      database.close();
   }
});

http.createServer(app).listen(app.get('port'), function(){
  console.log('서버가 시작되었습니다. 포트 : ' + app.get('port'));

  connectDB(); //DB연결 함수 호출
});
