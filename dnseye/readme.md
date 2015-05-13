#dnseye
****   

##introduction

1. Written by C.  
2. Based on snort-0.96.  
3. Add a function of monitoring all DNS requests in local LAN.  
4. Using a 4-level linklist to record source ip and domain name of DNS request packets.  

##build

1. sudo apt-get install libpcap-dev
2. cd dnseye
3. make

##example

		geeksword@ubuntu:~/code/traffic-analysis/dnseye$ make 
		geeksword@ubuntu:~/code/traffic-analysis/dnseye$ sudo ./dnseye 

		-*> Snort! <*-
		Version 0.96, By Martin Roesch (roesch@clark.net)
		Decoding Ethernet on interface eth0
		com	ubuntu	daisy
		com	weibo	
		cn	com	login.sina
		com	weibo	
		cn	com	login.sina
		com	weibo	passport
		com	mozilla	tiles.services
		com	mozilla	tiles.services
		com	weibo	passport
		com	linuxjournal	www
		com	linuxjournal	www
		com	linuxjournal	www
		cn	sinajs	img.t
		cn	sinajs	img.t
		com	linuxjournal	www
		com	googleapis	ajax
		com	googleadservices	partner
		com	googleadservices	partner
		com	quantserve	edge
		com	quantserve	edge
		com	linuxjournal	www
		com	baidu	
		com	baidu	www
		com	baidu	www
		com	linuxjournal	www
		com	bdstatic	ss1
		com	bdstatic	ss1
		com	googleapis	ajax
		com	linuxjournal	www
		com	linuxjournal	www
		com	google	www
		com	disqus	
		com	disqus	
		com	trueability	
		com	trueability	
		com	amazonaws	s3
		com	amazonaws	s3
		com	baidu	passport
		com	baidu	passport
		com	google	www
		cn	sinajs	js.t
		com	baidu	sp0
		com	baidu	sp0
		cn	sinajs	js1.t
		com	google	www
		cn	sinaimg	tp1
		cn	sinajs	js.t
		com	trueability	
		cn	sinajs	js2.t
		cn	sinajs	js1.t
		cn	com	beacon.sina
		cn	sinajs	js2.t
		com	mozilla	tiles.services
		com	weibo	api
		com	weibo	d
		com	weibo	game
		com	weibo	hot.plaza
		com	weibo	huati
		com	weibo	verified
		com	weibo	vip
		com	weibo	photo
		com	weibo	data
		com	weibo	m
		com	weibo	open
		com	weibo	rm.api
		com	weibo	e
		com	weibo	tui
		com	weibo	xueyuan
		com	weibo	help
		com	weibo	ir
		cn	sinaimg	tp3
		cn	sinaimg	tp4
		cn	sinaimg	tp2
		com	weibo	hr
		cn	com	news.sina
		com	weibo	service.account
		cn	sinaimg	tp4
		cn	gov	www.miibeian
		com	weibo	ting
		cn	ac	ict
		cn	sinaimg	tp2
		cn	ac	ict
		cn	sinaimg	s9
		com	weibo	s
		com	weibo	level.account
		com	weibo	club
		org	mozilla	support
		^CExiting...
		From: 192.168.6.128	Count: 87
		+org	Count:1
		-+mozilla.org	Count:1
		---support.mozilla.org
		+cn	Count:22
		-+ac.cn	Count:2
		---ict.ac.cn
		-+gov.cn	Count:1
		---www.miibeian.gov.cn
		-+sinaimg.cn	Count:7
		---s9.sinaimg.cn
		---tp2.sinaimg.cn
		---tp4.sinaimg.cn
		---tp3.sinaimg.cn
		---tp1.sinaimg.cn
		-+sinajs.cn	Count:8
		---js2.t.sinajs.cn
		---js1.t.sinajs.cn
		---js.t.sinajs.cn
		---img.t.sinajs.cn
		-+com.cn	Count:4
		---news.sina.com.cn
		---beacon.sina.com.cn
		---login.sina.com.cn
		+com	Count:64
		-+amazonaws.com	Count:2
		---s3.amazonaws.com
		-+trueability.com	Count:3
		-+disqus.com	Count:2
		-+google.com	Count:3
		---www.google.com
		-+bdstatic.com	Count:2
		---ss1.bdstatic.com
		-+baidu.com	Count:7
		---sp0.baidu.com
		---passport.baidu.com
		---www.baidu.com
		-+quantserve.com	Count:2
		---edge.quantserve.com
		-+googleadservices.com	Count:2
		---partner.googleadservices.com
		-+googleapis.com	Count:2
		---ajax.googleapis.com
		-+linuxjournal.com	Count:8
		---www.linuxjournal.com
		-+mozilla.com	Count:3
		---tiles.services.mozilla.com
		-+weibo.com	Count:27
		---club.weibo.com
		---level.account.weibo.com
		---s.weibo.com
		---ting.weibo.com
		---service.account.weibo.com
		---hr.weibo.com
		---ir.weibo.com
		---help.weibo.com
		---xueyuan.weibo.com
		---tui.weibo.com
		---e.weibo.com
		---rm.api.weibo.com
		---open.weibo.com
		---m.weibo.com
		---data.weibo.com
		---photo.weibo.com
		---vip.weibo.com
		---verified.weibo.com
		---huati.weibo.com
		---hot.plaza.weibo.com
		---game.weibo.com
		---d.weibo.com
		---api.weibo.com
		---passport.weibo.com
		-+ubuntu.com	Count:1
		---daisy.ubuntu.com


##about

- author: `geeksword`
- email: geeksword@163.com
- blog: http://onestraw.net
