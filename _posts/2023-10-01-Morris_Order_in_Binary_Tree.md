---
title: Morris Order in Binary Tree
date: 2023-10-01 9:42:38 +0800
categories: [STUDY, algorithm]
tags: [algorithm]     # TAG names should always be lowercase
---

## Morris Order in Binary Tree

Morris Order in Binary Tree


这是我的第一篇博客，主要是由于我在NYIT读硕士，有一门算法课，主要用于记录自己的想法，
1、二叉树的遍历
2、二叉树的Morris遍历
3、总结


二叉树的Morris遍历 主要步骤包括：
1、假设当前来到的节点为current，则第一次进入循环的节点为根节点。
2、如果current没有左孩子，打印节点的值。并且把current移动到他自己的current的右孩子(current=current.right)。
3、如果current有左孩子，找到左孩子的最最最右边的节点mostRight。也可以叫做前驱节点。
a)如果mostRight的右孩子为空，将mostRight的右孩子连接到current节点（mostRight.right=current），并且把current移动到他自己的current的左孩子(current=current.left)，并跳出while-循环。
b)如果mostRight的右孩子不为空，则它一定指向了current，这时候将mostRight的右孩子指向空（mostRight.right=current），并且把current移动到他自己的current的右孩子(current=current.right)。

这样就实现了非递归的中序遍历，并且满足了题目要求的时间复杂度和空间复杂度限制。这个算法的关键点在于利用空闲指针来解决分配stack空间的问题。
下面是用java代码来实现的功能


We could use the Morris loop to print out the key of each node.

There are some details.
1. Assuming that the currently arrived node is current, the node that enters the loop for the first time is the root node.
2. If the current has no left child, print the value of the node. And moves current to his own current's right child (current=current.right).
3. If the current has a left child, find the most right node mostRight of the left child. It can also be called a predecessor.
   3.1 If the right child of mostRight is empty, connect the right child of mostRight to the current node (mostRight.right=current), move the current to his own current's left child (current=current.left), and jump out of the while loop.
   3.2 If the right child of mostRight is not empty, it must point to the current. At this time, point the right child of mostRight to empty (mostRight.right=current) and move current to his own right child of current (current= current.right).
   In this way, non-recursive in-order traversal is achieved, and the time complexity is O(n), and space complexity is O(1). The key point of this algorithm is to use free pointers to solve the problem of allocating stack space.


The following is the implementation using Java code.
