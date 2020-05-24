package com.security.demosecurity.resourse;

public class AuthResponse implements Comparable{
    String authToken;

    public String getAuthToken() {
        return authToken;
    }

    public void setAuthToken(String authToken) {
        this.authToken = authToken;
    }


    @Override
    public int compareTo(Object o) {
        return 0;
    }
}
