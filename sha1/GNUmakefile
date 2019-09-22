#################################################################################
# @brief makefileのテンプレートです...
# @note  GNU Make 3.81で動作確認しました
# @note  あんまり複雑なことはしません
# @note  以下のサイトを参考にしました
#        http://urin.github.io/posts/2013/simple-makefile-for-clang/
# @note  わからないコマンドがあったらGNU Make(O'reilly)を参考にしてください
# @date  作成日     : 2016/02/03
# @date  最終更新日 : 2016/02/03
#################################################################################


CC      = g++  
CFLAGS  = -Wall -Wextra -std=c++17 -O3 -MMD -MP
SCRS    = 
OBJS    = main.o      # 複数指定できます
INC     = #-I./include
TARGET  = main
LIBS    =
DEPENDS = $(OBJS:.o=.d)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(TARGET): $(OBJS) $(LIBS)
	$(CC) -o $@ $^ 

clean:
	rm -f $(TARGET) $(OBJS) $(DEPENDS)

-include $(DEPENDS)

