import 'dart:collection';
import 'dart:convert';
import 'dart:io';


void main(List<String> args) {
  
  //load file names
  String truthFile = args[0];
  String sguilFile = args[1];

  //empty lists of record objects
  List<Truth> truthRecords = new List();
  List<String> oneRecord = new List();

  // read truth data file into a list of lines
  var lines = new File(truthFile).readAsLinesSync();

  lines.forEach( (line) {
    if(line == "") {
      //handle new record
      var id = oneRecord[0].split(":")[1].trim();
      var date = oneRecord[1].split(":")[1].trim();
      var times = oneRecord[4].split(":");
      var time = times[1].trim() + ":" + times[2] + ":" + times[3];
      var durSplits = oneRecord[5].split(":");
      Duration duration = new Duration(
        hours: int.parse(durSplits[1]), 
        minutes: int.parse(durSplits[2]),
        seconds: int.parse(durSplits[3]));

      var attacker = normalizeIP(oneRecord[6].split(":")[1].trim());
      var victim = normalizeIP(oneRecord[7].split(":")[1].trim());

      //TODO parse At_Victim: ports
      List<int> ports = [];
      String portList = oneRecord[11].split(":")[1].trim();
      if(portList.length > 0) {
          print("Portlist for parsing: $portList");
          List<String> portSplits = portList.split(", ");
          portSplits.forEach((split) {
              String s = split.substring(0, split.indexOf("{"));
              if(s.contains("/")) {
                  s = s.substring(0, s.indexOf("/"));
              }
    
              if(s != "i"){
                 if(s.contains("-")){
                     int begin = int.parse(s.substring(0, s.indexOf("-")));
                     int end = int.parse(s.substring(s.indexOf("-") + 1));
                     for(int index = begin; index <= end; index++){
                         ports.add(index);
                     }
                 } else {
                     print("Parsing $s");
                     ports.add(int.parse(s));
                 }
              }
          });
      }

      //new truth record
      var truth = new Truth(id, date, time, duration, 
          attacker, victim, ports);
      //print("Truth record: $truth");
      truthRecords.add(truth);
      
      //reset record lines
      oneRecord.clear();
    } else {
      //add line to record lines
      oneRecord.add(line);
    }
  });

  print("Culling truth dates we don't care about");
  truthRecords.removeWhere((truth) => !truth.id.startsWith("43"));
  
  print("Truth count: ${truthRecords.length}");
  print("First ${truthRecords.first}");
  print("Last ${truthRecords.last}");

  //new lists of snort records
  List<Snort> snortRecords = new List();
  oneRecord.clear();

  //read snort export data file into a list of lines
  lines = new File(sguilFile).readAsLinesSync();

  lines.forEach( (line) {
    if(line.startsWith("---------") && oneRecord.length > 0 ) {
      //handle new record
      var line1Splits = oneRecord[0].split(" ");
      var id = line1Splits[1].trim();
      var date = line1Splits[2].trim();
      var time = line1Splits[3].trim();

      var line2Splits = oneRecord[2].split(" -> ");
      var attacker = line2Splits[0].trim();
      var victim = line2Splits[1].trim();

      //TODO parse destination ports

      var snort = new Snort(id, date, time, attacker, victim);
      //print("Snort record: $snort");
      snortRecords.add(snort);
      
      //reset record lines
      oneRecord.clear();
    } else if (!line.startsWith("-------")) {
      //add line to record lines
      oneRecord.add(line);
    }

  });

  print("Snort count: ${snortRecords.length}");
  print("First ${snortRecords.first}");
  print("Last ${snortRecords.last}");

  int minSeconds = 5 * 60 * 60 - 10;
  int maxSeconds = 5 * 60 * 60 + 10;
  //for each Truth, look for match in snorts
  List<Truth> matches = truthRecords.where((truth) {
      return snortRecords.any((snort) =>
        truth.attacker == snort.attacker &&
        truth.victim == snort.victim &&
        snort.dateTime.difference(truth.dateTime).inSeconds > minSeconds &&
        snort.dateTime.difference(truth.dateTime).inSeconds < maxSeconds
        );
  });

  var matchOutput = matches.join("\n");
  print("Final matches:\n$matchOutput");
}

class Truth {
  String id;
  String date;
  String time;
  Duration duration;
  String attacker;
  String victim;
  DateTime dateTime;
  List<int> ports;

  Truth(this.id, this.date, this.time, this.duration, 
      this.attacker, this.victim, this.ports){
    var dateSplits = date.split("/");
    var ISO = "${dateSplits[2]}-${dateSplits[0]}-${dateSplits[1]}";
    dateTime = DateTime.parse("$ISO $time");

  }

  String toString() => "ID: $id, Date $date, Time $time, Attacker $attacker, " +
    "Victim $victim";
}

class Snort {
  String id;
  String date;
  String time;
  String attacker;
  String victim;
  DateTime dateTime;

  Snort(this.id, this.date, this.time, this.attacker, this.victim){
    dateTime = DateTime.parse("$date $time");
  }


  String toString() => "ID: $id, Date $date, Time $time, Attacker $attacker, " +
    "Victim $victim";

}

String normalizeIP(String input){
  List<String> splits = input.split(".");
  try{
    List<Int> ints = splits.map((s) => int.parse(s));
    return ints.join(".");
  } catch (_) {
    return input;
  }
}

