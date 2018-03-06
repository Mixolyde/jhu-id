import 'dart:collection';
import 'dart:convert';
import 'dart:io';


void main(List<String> args) {
  
  //load file one
  String truthFile = args[0];
  String sguilFile = args[1];

  List<Truth> truthRecords = new List();
  List<String> oneRecord = new List();

  var lines = new File(truthFile).readAsLinesSync();

  lines.forEach( (line) {
      if(line == "") {
        //handle new record
        var id = oneRecord[0].split(":")[1].trim();
        var date = oneRecord[1].split(":")[1].trim();
        var times = oneRecord[4].split(":");
        var time = times[1].trim() + ":" + times[2] + ":" + times[3];

        //TODO normalize IP addresses
        var attacker = oneRecord[6].split(":")[1].trim();
        var victim = oneRecord[7].split(":")[1].trim();

        //TODO parse At_Victim: ports

        var truth = new Truth(id, date, time, attacker, victim);
        print("Truth record: $truth");
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


}

class Truth {
  String id;
  String date;
  String time;
  String attacker;
  String victim;

  Truth(this.id, this.date, this.time, this.attacker, this.victim);

  String toString() => "ID: $id, Date $date, Time $time, Attacker $attacker, " +
    "Victim $victim";
}
