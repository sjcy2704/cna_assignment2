#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* Copied from gbn.c */

#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */

#define SEQSPACE 12     /* SEQSPACE must be >= 2 * WINDOWSIZE */

#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for ( i=0; i<20; i++ )
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}


/********* Sender (A) variables and functions ************/

static struct pkt A_buffer[SEQSPACE];  /* array for storing packets waiting for ACK */
static bool A_ackeds[SEQSPACE];        /* array for storing whether a packet has been ACKed */
static float A_expiries[SEQSPACE];     /* array for storing the expiry time of each packet */
static bool A_timer_is_active = false;  /* flag for whether the timer is active */

static int A_nextseqnum = 0;           /* the next sequence number to be used by the sender */
static int A_base = 0;                 /* the base of the window */

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  // calculate current window size: how many unACKed packets are in-flight.
  // use modulo to handle sequence number wrap-around correctly.
  int window_size = (A_nextseqnum + SEQSPACE - A_base) % SEQSPACE;
  if (window_size >= WINDOWSIZE) {
    // If the window is full, drop the message (i.e., don't send it).
    if (TRACE > 0) {
      printf("----A: window is full, message dropped\n");
    }

    // update global counter for dropped messages because of full window
    window_full++;
    return;
  }

  // construct packet to send 
  struct pkt p;
    p.seqnum = A_nextseqnum; // assign sequence number
    p.acknum = NOTINUSE; // this is a packet, not an ACK

    // copy 20 byte payload from the message into the packet
    for (int i = 0; i < 20; i++)
        p.payload[i] = message.data[i]; // assign to payload
      
    p.checksum = ComputeChecksum(p); // compute checksum to detect corruption later

    // save the packet in the sender's buffer so it can be retransmitted if needed
    A_buffer[A_nextseqnum] = p;

    // packet not acknowledged yet
    A_ackeds[A_nextseqnum] = false;


    // send packet to simulator
    if (TRACE > 0) {
      printf("----A: sending packet %d to layer 3\n", p.seqnum);
    }
    tolayer3(A, p);

    // set a simulated countdown timer for this packet.
    // since the emulator allows only one hardware timer, we simulate per-packet timers
    // by tracking how much time remains for each packet, and checking it in A_timerinterrupt().
    A_expiries[A_nextseqnum] = RTT;

    // if this is the first packet, start the tick timer.
    if (!A_timer_is_active) {
      starttimer(A, 1.0);
      A_timer_is_active = true;
    }

    // get next sequence number, wrap back to 0
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
}


/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
}

void A_init(void)
{
  // initialize sender's window base (first unacked packet)
  A_base = 0;

  // initialize sender's next sequence number to be used
  A_nextseqnum = 0;

  // initialize timer state
  A_timer_is_active = false;

  for (int i = 0; i < SEQSPACE; i++) {
    A_ackeds[i] = false; // initialize acked state for all packets (no packets have been acked)
    A_expiries[i] = -1; // initialize expiry times for all packets (-1 indicating is inactive)
  }

  if (TRACE > 0) {
    printf("----A: initialized\n");
  }
}



/********* Receiver (B)  variables and procedures ************/

static int expectedseqnum; /* the sequence number expected next by the receiver */
static int B_nextseqnum;   /* the sequence number for the next packets sent by B */


/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
}

/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

/* Note that with simplex transfer from a-to-B, there is no B_output() */
void B_output(struct msg message)
{
}

/* called when B's timer goes off */
void B_timerinterrupt(void)
{
}
