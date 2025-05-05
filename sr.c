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
  struct pkt p;
  int i;
  /* calculate current window size: how many unACKed packets are in-flight.
  use modulo to handle sequence number wrap-around correctly. */
  int window_size = (A_nextseqnum + SEQSPACE - A_base) % SEQSPACE;
  printf("A_output: window_size = %d, A_base = %d, A_nextseq = %d\n",
    window_size, A_base, A_nextseqnum);
  if (window_size >= WINDOWSIZE) {
    /* If the window is full, drop the message (i.e., don't send it). */
    if (TRACE > 0) {
      printf("----A: window is full, message dropped\n");
    }

    /* update global counter for dropped messages because of full window */
    window_full++;
    return;
  }

  /* construct packet to send */
  p.seqnum = A_nextseqnum; /* assign sequence number */
  p.acknum = NOTINUSE; /* this is a packet, not an ACK */

  /* copy 20 byte payload from the message into the packet */
  for (i = 0; i < 20; i++)
    p.payload[i] = message.data[i]; /* assign to payload */
    
  p.checksum = ComputeChecksum(p); /* compute checksum to detect corruption later */

  /* save the packet in the sender's buffer so it can be retransmitted if needed */
  A_buffer[A_nextseqnum] = p;

  /* packet not acknowledged yet */
  A_ackeds[A_nextseqnum] = false;


  /* send packet to simulator */
  if (TRACE > 0) {
    printf("----A: sending packet %d to layer 3\n", p.seqnum);
  }
  tolayer3(A, p);

  /* set a simulated countdown timer for this packet.
  since the emulator allows only one hardware timer, we simulate per-packet timers
  by tracking how much time remains for each packet, and checking it in A_timerinterrupt(). */
  A_expiries[A_nextseqnum] = RTT;

  /* if this is the first packet, start the tick timer. */
  if (!A_timer_is_active) {
    starttimer(A, 1.0);
    A_timer_is_active = true;
  }

  /* get next sequence number, wrap back to 0 */
  A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
}


/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
  int i;
  int acknum;
  bool has_unacked;
  /* check if packet is corrupted */
  if (IsCorrupted(packet)) {
    if (TRACE > 0)
      printf("----A: Corrupted ACK %d received, ignored\n", packet.acknum);
    return;
  }

  total_ACKs_received++;
  acknum = packet.acknum;

  /* we need to only handle the ACKs for packets that are currently in the sender's window 
  if packet is already acknowledge, then is a duplicate ACK */
  if (!A_ackeds[acknum]) {
    A_ackeds[acknum] = true;
    A_expiries[acknum] = -1.0; /* Stop simulated timer for this packet */
    new_ACKs++;

    if (TRACE > 0)
      printf("----A: ACK %d received and marked as acknowledged\n", acknum);
  } else {
    if (TRACE > 0)
      printf("----A: Duplicate ACK %d received, ignored\n", acknum);
      return;
  }

  /* in selective repeat, the sender window base moves forward only if the base packet (A_base) has been acknowledged
  because the window is circular (going back to 0), we must use modulo to handle then wrap cleanly
  we continue sliding the base forward until we find the first unACKed packet */
  while (A_ackeds[A_base]) {
      A_ackeds[A_base] = false;          /* reset slot for reuse */
      A_expiries[A_base] = -1.0;         /* cancel timer */
      A_base = (A_base + 1) % SEQSPACE;  /* slide the base forward, the modulo ensures that it wraps back to 0 */
  }

  /* the emulator only allows ONE real timer, so we simulate per-packet timers with a 1-second global tick
  if any unACKed packets remain in the window, we keep the timer running. if all are ACKed, we can stop it. */
  has_unacked = false;
  /* check if there is a packet with active timers */
  for (i = 0; i < WINDOWSIZE; i++) {
    int index = (A_base + i) % SEQSPACE;

    if (A_expiries[index] > 0) {
      has_unacked = true;
      break;
    }
  }

  /* start timer if there are unACKed packets and timer is not active */
  if (has_unacked && !A_timer_is_active) {
    starttimer(A, 1.0);
    A_timer_is_active = true;
  } else if (!has_unacked) {
    /* stop timer if all packets are ACKed */
    stoptimer(A);
    A_timer_is_active = false;
  }
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  if (TRACE > 0)
    printf("----A: Timer tick, checking for expired packets...\n");

  int i; 
  bool any_unacked = false;

  for (i = 0; i < WINDOWSIZE; i++) {
    /* calculate index */
    int index = (A_base + i) % SEQSPACE;

    /* only process packets that are not acknowledged and have an active timer */
    if (!A_ackeds[index] && A_expiries[index] > 0) {
      A_expiries[index] -= 1.0;  /* tick down */

      /* if timer expired, retransmit */
      if (A_expiries[index] <= 0) {
        if (TRACE > 0)
          printf("----A: Timeout for packet %d, retransmitting\n", index);

        tolayer3(A, A_buffer[index]);   /* retransmit the packet */
        packets_resent++;               /* update global counter for retransmitted packets */
        A_expiries[index] = RTT;    /* restart timer */
      }

      any_unacked = true;
    }
  }

  /* after checking all the packets, if any are unacknowledged, keep the timer running, else stop it */
  if (any_unacked) {
    starttimer(A, 1.0);
    A_timer_is_active = true;
  } else {
    stoptimer(A);
    A_timer_is_active = false;
  }

}

void A_init(void)
{
  int i;
  /* initialize sender's window base (first unacked packet) */
  A_base = 0;

  /* initialize sender's next sequence number to be used */
  A_nextseqnum = 0;

  /* initialize timer state */
  A_timer_is_active = false;

  for (i = 0; i < SEQSPACE; i++) {
    A_ackeds[i] = false; /* initialize acked state for all packets (no packets have been acked) */
    A_expiries[i] = -1; /* initialize expiry times for all packets (-1 indicating is inactive) */
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
  struct pkt sendpkt;
  int i;

  /* if not corrupted and received packet is in order */
  if  ( (!IsCorrupted(packet))  && (packet.seqnum == expectedseqnum) ) {
    if (TRACE > 0)
      printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum);
    packets_received++;

    /* deliver to receiving application */
    tolayer5(B, packet.payload);

    /* send an ACK for the received packet */
    sendpkt.acknum = expectedseqnum;

    /* update state variables */
    expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
  }
  else {
    /* packet is corrupted or out of order resend last ACK */
    if (TRACE > 0)
      printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    if (expectedseqnum == 0)
      sendpkt.acknum = SEQSPACE - 1;
    else
      sendpkt.acknum = expectedseqnum - 1;
  }

  /* create packet */
  sendpkt.seqnum = B_nextseqnum;
  B_nextseqnum = (B_nextseqnum + 1) % 2;

  /* we don't have any data to send.  fill payload with 0's */
  for ( i=0; i<20 ; i++ )
    sendpkt.payload[i] = '0';

  /* computer checksum */
  sendpkt.checksum = ComputeChecksum(sendpkt);

  /* send out packet */
  tolayer3 (B, sendpkt);
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
  expectedseqnum = 0;
  B_nextseqnum = 1;
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
