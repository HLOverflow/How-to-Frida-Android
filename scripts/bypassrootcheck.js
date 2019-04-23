/*
  1 package com.scottyab.rootbeer;
  2 
  3 import android.content.Context;
  4 import android.content.pm.PackageManager;
  5 import android.content.pm.PackageManager.NameNotFoundException;
  6 import android.os.Build;
  7 import com.scottyab.rootbeer.util.QLog;
  8 import java.io.BufferedReader;
  9 import java.io.File;
 10 import java.io.IOException;
 11 import java.io.InputStream;
 12 import java.io.InputStreamReader;
 13 import java.util.ArrayList;
 14 import java.util.Arrays;
 15 import java.util.HashMap;
 16 import java.util.List;
 17 import java.util.NoSuchElementException;
 18 import java.util.Scanner;
 19 
 20 public class RootBeer {
 ...
 289     public boolean isRooted() {
 290         return detectRootManagementApps() || detectPotentiallyDangerousApps() || checkForBinary("su") || check    ForBinary("busybox") || checkForDangerousProps() || checkForRWPaths() || detectTestKeys() || checkSuExists() |    | checkForRootNative() || checkForMagiskBinary();
 291     }
 * */

Java.perform(function(){ 
	var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer"); 
	RootBeer.isRooted.implementation = function(){
		console.log("RootBeer isRooted returns false");
		return false;
	}
	 
});
