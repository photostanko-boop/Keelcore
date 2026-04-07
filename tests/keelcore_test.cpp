#include <gtest/gtest.h>  
#include "Keelcore.h"  // Assuming this is the header where Keelcore class is defined  
  
class KeelcoreTest : public ::testing::Test {  
protected:  
    Keelcore* keelcore;  
  
    void SetUp() override {  
        keelcore = new Keelcore();  
    }  
  
    void TearDown() override {  
        delete keelcore;  
    }  
};  
  
TEST_F(KeelcoreTest, InitialState) {  
    EXPECT_EQ(keelcore->getState(), State::INITIAL);  // Assuming INITIAL is a valid state  
}  
  
TEST_F(KeelcoreTest, TransitionToActive) {  
    keelcore->start();  
    EXPECT_EQ(keelcore->getState(), State::ACTIVE);  // Check transition to ACTIVE state  
}  
  
TEST_F(KeelcoreTest, TransitionToIdle) {  
    keelcore->start();  
    keelcore->pause();  
    EXPECT_EQ(keelcore->getState(), State::IDLE);  // Check transition to IDLE state  
}  
  
TEST_F(KeelcoreTest, TransitionToStopped) {  
    keelcore->stop();  
    EXPECT_EQ(keelcore->getState(), State::STOPPED);  // Check transition to STOPPED state  
}  
  
// Add more test cases as needed to cover all transitions...