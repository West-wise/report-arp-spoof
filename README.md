핸드폰에서 핫스팟을 사용하여 태블릿과 노트북을 연결하였습니다.

2023-07-27 태블릿에서 [Ping]이라는 앱을 사용해서 구글로 핑을 때렸고 ./send-arp-test eth0 [sip] [tip]를 실행하면 Ping 앱상에서는 Request Timeout이 뜨면서 핑이 잠시 멈춥니다(한 2~3초 정도) Wireshark에서도 ip.src == [태블릿 ip]로 하면 잡히는게 없는데 arp로 필터링을하면 파일을 실행할 때마다 게이트웨이에서 arp패킷이 날라오는것을 확인할 수 있었습니다. 현재 이상황으로 보아 arp테이블은 변조가 된것 같지만 제대로 변조가 되지는 않은것 같습니다.. 현재 한개의 타겟만을 대상으로 하였으며 여러개의 타겟은 계속 업데이트 할 것입니다.

2023 07-29 sip와 tip를 최대 5개까지 받을 수 있도록 구성하였습니다. 노트북 , 태블릿pc까지 사용하여 태블릿과 노트북 모두 8.8.8.8로 ping을 날렸을때 Attacker의Wireshark에서 핑이 잡히는것을 확인하였으며 sender노트북에서 arp -a | find <게이트웨이 ip> 해서 arp테이블이 변조되는 것 또한 확인하였습니다.

기존에 arp에 대해서는 알고있었으나 이론으로만 공부하여 막상 arp테이블을 변조하려고 하니 머릿속에서 뭔가 꼬이는 느낌을 받았습니다..ㅎㅎ 다른 과제도 있고 실질적으로 비는 시간이 많이 없어서 급하게 하느라 생각나는대로 코드를 짜서 좀 난잡한 코드라고 생각합니다. 그래도 이번 과제를 통해서 arp에 대해서 재정립하는 기회를 가질 수 있었던것 같습니다. 추가적으로 이와 비슷한 방법으로 리버스 ARP또한 변조가 가능할지 궁금해졌습니다. 될것같긴한데 검증이 가능한 방법을 모르겠습니다.

2023-08-06 report-send-arp의 파일에서 MAC과 IP가 쓰이는 곳을 멘토님의 Mac,Ip로 교체하였습니다. 또한 Mac을 반환하는 함수들을 Macutills헤더파일로 분류하였습니다. 이 과정에서 오랜시간 실수가 발생해서 시간을 많이 잡아먹었습니다..


2023-08-10
