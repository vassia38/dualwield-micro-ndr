# build executable when user executes "make"
dumbdropper: dumbdropper.o
	$(CXX) $(LDFLAGS) dumbdropper.o -o dumbdropper $(LIBS)
dumbdropper.o: dumbdropper.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o dumbdropper.o

# remove object files and executable when user executes "make clean"
clean:
	rm *.o dumbdropper
