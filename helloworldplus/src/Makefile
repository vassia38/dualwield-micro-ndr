# build helloworld executable when user executes "make"
helloworldplus: helloworldplus.o
	$(CXX) $(LDFLAGS) helloworldplus.o -o helloworldplus $(LIBS)
helloworldplus.o: helloworldplus.cpp
	$(CXX) $(CXXFLAGS) -c helloworldplus.cpp

# remove object files and executable when user executes "make clean"
clean:
	rm *.o helloworldplus
