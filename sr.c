#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

/* Selective Repeat Implementation based on gbn.c */

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

static int A_nextseqnum = 0;           /* the next sequence number to be used by the sender */
static int A_base = 0;                 /* the base of the window */
static int unacked_packets = 0;

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt p;
  int i;
  /* calculate current window size: how many unACKed packets are in-flight.
  use modulo to handle sequence number wrap-around correctly. */
  int window_size = (A_nextseqnum + SEQSPACE - A_base) % SEQSPACE;

  /* debug print to check if variables get updated properly */
  if (TRACE == 1) {
    printf("A_output: window_size = %d, A_base = %d, A_nextseq = %d\n",
      window_size, A_base, A_nextseqnum);
  }

  if (window_size >= WINDOWSIZE) {
    /* If the window is full, drop the message (i.e., don't send it). */
    if (TRACE > 0) {
      printf("----A: New message arrives, send window is full\n");
    }

    /* update global counter for dropped messages because of full window */
    window_full++;
    return;
  }

  if (TRACE > 1) {
    printf("----A: New message arrives, send window is not full, send new messge to layer 3!\n");
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
    printf("Sending packet %d to layer 3\n", p.seqnum);
  }
  tolayer3(A, p);

  /* if this is the first packet, start the tick timer. */
  if (A_base == A_nextseqnum) {
    starttimer(A, RTT);
  }

  /* get next sequence number, wrap back to 0 */
  A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  unacked_packets++;
}


/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
  int acknum;
  /* check if packet is corrupted */
  if (IsCorrupted(packet)) {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
    return;
  }

  acknum = packet.acknum;

  /* check if the ACK is out of range */
  if (acknum < 0 || acknum >= SEQSPACE) {
    if (TRACE == 0)
      printf("----A: ACK %d is out of range, do nothing!\n", acknum);
    return;
  }

  if (TRACE > 0) {
    printf("----A: uncorrupted ACK %d is received\n", acknum);
  }

  total_ACKs_received++;

  /* we need to only handle the ACKs for packets that are currently in the sender's window 
  if packet is already acknowledge, then is a duplicate ACK */
  if (!A_ackeds[acknum]) {
    A_ackeds[acknum] = true;
    new_ACKs++;
    unacked_packets--;

    if (TRACE > 0) {
      printf("----A: ACK %d is not a duplicate\n", acknum);
    }
  } else {
    if (TRACE > 0) {
      printf("----A: duplicate ACK received, do nothing!\n");
    }
  }

  /* in selective repeat, the sender window base moves forward only if the base packet (A_base) has been acknowledged
  because the window is circular (going back to 0), we must use modulo to handle then wrap cleanly
  we continue sliding the base forward until we find the first unACKed packet */
  while (A_ackeds[A_base]) {
      A_ackeds[A_base] = false;          /* reset slot for reuse */
      A_base = (A_base + 1) % SEQSPACE;  /* slide the base forward, the modulo ensures that it wraps back to 0 */
  }

  stoptimer(A);
  if (unacked_packets > 0) {
    starttimer(A, RTT);
  }
}

void A_timerinterrupt(void)
{
  if (TRACE > 0) {
    printf("----A: time out,resend packets!\n");
    printf("---A: resending packet %d\n", A_buffer[A_base].seqnum);
  }

  tolayer3(A, A_buffer[A_base]); /* resend the packet */
  packets_resent++; /* update global counter for resent packets */

  starttimer(A, RTT); /* restart the timer */
}

void A_init(void)
{
  int i;
  /* initialize sender's window base (first unacked packet) */
  A_base = 0;

  /* initialize sender's next sequence number to be used */
  A_nextseqnum = 0;

  unacked_packets = 0;

  for (i = 0; i < SEQSPACE; i++) {
    A_ackeds[i] = false; /* initialize acked state for all packets (no packets have been acked) */
  }
}


/********* Receiver (B)  variables and procedures ************/

static struct pkt B_buffer[SEQSPACE];
static bool B_received[SEQSPACE];
static int B_expected_base = 0;
static int B_nextseqnum = 0;

void B_input(struct pkt packet)
{
  struct pkt sendpkt;
  int i;
  int seq = packet.seqnum;

  /* if packet is corrupted we just ignore it and do nothing else */
  if (IsCorrupted(packet)) {
    return;
  }

  packets_received++; /* update global counter for received packets */

  if (TRACE > 0) printf("----B: packet %d is correctly received, send ACK!\n", seq);

  /* save the packet in the buffer even if it hasn't been recieved even if its out of order since SR allows that */
  if (!B_received[seq]) {
    B_buffer[seq] = packet;
    B_received[seq] = true;
  }

  /* attempt to deliver packets to layer 5 in order */
  /* while having the expected packet, it gets delivered and move the base forward */
  while (B_received[B_expected_base]) {
    tolayer5(B, B_buffer[B_expected_base].payload); /* deliver the packet to layer 5 in order */
    B_received[B_expected_base] = false; /* reset the received flag */
    B_expected_base = (B_expected_base + 1) % SEQSPACE; /* move the base forward */
  }

  sendpkt.seqnum = 0; /* sender does not use seqnum*/
  sendpkt.acknum = seq; /* ACK the sequence number of the packet */
  for (i = 0; i < 20; i++) sendpkt.payload[i] = 0; /* payload is not used so just set to zeros */
  sendpkt.checksum = ComputeChecksum(sendpkt);
  tolayer3(B, sendpkt);
}

void B_init(void)
{
  int i;
  B_expected_base = 0;
  B_nextseqnum = 1;
  for (i = 0; i < SEQSPACE; i++)
    B_received[i] = false;
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
