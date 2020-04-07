# RSA--
package main
type Window	 interface {
	showWindow()
}
//2.创建加解密的界面类
type ComWindow struct {
	Window
	*walk.MainWindow //主题窗
}
//3. 展示加解密成功失败提示信息的界面类
type LabWindow struct {
	Window
}
//4.创建加解密界面类对象
func Show(window_Type string) {
	var Win Window
	switch window_Type{
	case "main_window":
		Win=&ComWindow{}
	case "lab_window":
		Win=&LabWindow{}
	default:
		fmt.Println("加解密错误")
	}
	Win.showWindow()
}

var Text string         //保存提示信息的
func (com *ComWindow)showWindow() {
	var Plaintext ,Public ,ciphertext ,secretkey *walk.LineEdit
	var Plaintextopen ,Publicopen ,ciphertextopen ,secretkeyopen ,encryption, Decrypt *walk.PushButton
	pathWindow:=new(ComWindow)
	err:=declarative.MainWindow{
		AssignTo:&pathWindow.MainWindow,
		Title:"RSA_4096 加密助手",
		MinSize:declarative.Size{480,230},
		//布局
		Layout:declarative.HBox{},
		Children:[]declarative.Widget{
			declarative.Composite{
				Layout:declarative.Grid{Columns:2,Spacing:10},
				Children:[]declarative.Widget{
					declarative.LineEdit{
						AssignTo:&Plaintext,
						Text:"PlainText",
					},
					declarative.PushButton{
						AssignTo:&Plaintextopen,
						Text:"Open",
						OnClicked: func() {
							filePath := pathWindow.OpenFilePublic()
							Plaintext.SetText(filePath)
						},
					},
					declarative.LineEdit{
						AssignTo:&Public,
						Text:"HerPubKey:",
					},
					declarative.PushButton{
						AssignTo:&Publicopen,
						Text:"Open",
						OnClicked: func() {
							filePath := pathWindow.OpenFilePublic()
							Public.SetText(filePath)
						},
					},
					declarative.LineEdit{
						AssignTo:&ciphertext,
						Text:"CipherText:",
					},
					declarative.PushButton{
						AssignTo:&ciphertextopen,
						Text:"Open",
						OnClicked: func() {
							filePath := pathWindow.OpenFilePublic()
							ciphertext.SetText(filePath)
						},
					},
					declarative.LineEdit{
						AssignTo:&secretkey,
						Text:"MyKey:",
					},
					declarative.PushButton{
						AssignTo:&secretkeyopen,
						Text:"Open",
						OnClicked: func() {
							filePath := pathWindow.OpenFilePublic()
							secretkey.SetText(filePath)
						},
					},
				},
			},
			declarative.Composite{
				Layout:declarative.Grid{Rows:2,Spacing:40},
				Children:[]declarative.Widget{
					declarative.PushButton{
						AssignTo:&encryption,
						Text:"RSA 加密(D:/)",
						OnClicked: func() {
							pathWindow.EncryptionKey(Plaintext.Text(),Public.Text())
							//Text="文件加密成功"
							//Show("main_window")
						},
					},
					declarative.PushButton{
						AssignTo:&Decrypt,
						Text:"RSA 解密(D:/)",
						OnClicked: func() {
							pathWindow.DecryptKey(ciphertext.Text() ,secretkey.Text())
							//Text="文件解密成功"
							//Show("main_window")
						},
					},
				},

			},
		},
	}.Create()//创建窗口
	if err!=nil{
		fmt.Println(err)
	}
	//窗口的展示，需要通过坐标来指定
	pathWindow.SetX(650)
	pathWindow.SetY(300)
	pathWindow.Run()
}
//选择文件目录
func (Public *ComWindow)OpenFilePublic()(filePath string){
	//1：创建文件对话框(FileDialog)的对象
	dlg := new(walk.FileDialog)
	dlg.Title = "选择文件"
	dlg.Filter = "所有文档(*.*)|*.*|文本文档(*.pem)|*.pem"
	//2：打开文件对话框
	dlg.ShowOpen(Public)
	//3：获取选中的文件
	filePath = dlg.FilePath
	return filePath
}

//实现文件加密操作
func (mv *ComWindow)EncryptionKey(fileName string, pubkey string) { //plainText是第二个文本框中的值
	// 1. 打开文件, 并且读出文件内容
	data := Readfile(fileName)
	key := Readfile(pubkey)
	// 2. pem解码
	block, _ := pem.Decode(key)
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//断言类型转换
	pubKey := pubInterface.(*rsa.PublicKey)
	// 3. 使用公钥加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		panic(err)
	}
	//转成string类型
	cip := hex.EncodeToString(cipherText)
	file,_:=os.Create("D:/cipherText.txt")
	defer file.Close()
	file.WriteString(cip)
}

//收到对方密文，实现个人私钥解密操作
func (mv *ComWindow)DecryptKey(cipherText string, fileName string){
	// 1. 打开文件, 并且读出文件内容
	date1 := Readfile(cipherText)
	key1 := Readfile(fileName)
	// 2. pem解码
	block, _ := pem.Decode(key1)
	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	cip,_ := hex.DecodeString(string(date1))
	// 3. 使用私钥解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privKey, cip)
	file,_:=os.Create("D:/Plaintext.txt")
	defer file.Close()
	file.WriteString(string(plainText))
}

//读文件方法
func Readfile(fileName string) []byte {
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	fileInfo, err := file.Stat() //file.Stat读文件大小
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	file.Read(buf)
	file.Close()
	return  buf
}

//RSA生成密钥对
func GenerateRsaKey(keySize int) {
	// 1. 使用rsa中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}
	//fmt.Println(privateKey)
	// 2. 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	// 3. 要组织一个pem.Block
	block := pem.Block{
		Type : "rsa private key", // 这个地方写个字符串就行
		Bytes : derText,
	}
	// 4. pem编码
	file1, err := os.Create("D:/privateKey.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file1, &block)
	file1.Close()

	// ============ 公钥 ==========
	// 1. 从私钥中取出公钥
	publicKey := privateKey.PublicKey
	// 2. 使用x509标准序列化
	derstream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	// 3. 将得到的数据放到pem.Block中
	block = pem.Block{
		Type : "rsa public key",
		Bytes : derstream,
	}
	// 4. pem编码
	file2, err2 := os.Create("D:/publicKey.pem")
	if err2 != nil {
		panic(err2)
	}
	pem.Encode(file2, &block)
	file2.Close()
}

func main() {
	GenerateRsaKey(4096)
	Show("main_window")
}
